const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { body, validationResult } = require('express-validator');
const prisma = require('../prisma');
const { authenticate } = require('../middleware/auth');
const crypto = require('crypto');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../utils/email');
const { logAudit } = require('../utils/audit');

const router = express.Router();

// ==================== REGISTRACE ====================
router.post('/register', [
  body('email').isEmail().withMessage('Neplatný e-mail.'),
  body('password').isLength({ min: 8 }).withMessage('Heslo musí mít alespoň 8 znaků.'),
  body('firstName').trim().notEmpty().withMessage('Jméno je povinné.'),
  body('lastName').trim().notEmpty().withMessage('Příjmení je povinné.'),
  body('dateOfBirth').isISO8601().withMessage('Neplatné datum narození.'),
  body('addressStreet').trim().notEmpty().withMessage('Ulice je povinná.'),
  body('addressCity').trim().notEmpty().withMessage('Město je povinné.'),
  body('addressZip').trim().notEmpty().withMessage('PSČ je povinné.'),
  body('phone').trim().notEmpty().withMessage('Telefon je povinný.'),
  body('isPermanentResident').isBoolean().withMessage('Trvalé bydliště musí být boolean.'),
  body('gdprConsent').equals('true').withMessage('Musíte souhlasit se zpracováním osobních údajů.'),
  body('rulesConsent').equals('true').withMessage('Musíte souhlasit s pravidly systému.'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email, password, firstName, lastName, dateOfBirth, addressStreet,
            addressCity, addressZip, phone, isPermanentResident, gdprConsent, rulesConsent } = req.body;

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return res.status(409).json({ error: 'Uživatel s tímto e-mailem již existuje.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const emailVerifyToken = uuidv4();

    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        firstName,
        lastName,
        dateOfBirth: new Date(dateOfBirth),
        addressStreet,
        addressCity,
        addressZip,
        phone,
        isPermanentResident: isPermanentResident === true || isPermanentResident === 'true',
        emailVerifyToken,
        gdprConsent: true,
        gdprConsentDate: new Date(),
        rulesConsent: true,
        rulesConsentDate: new Date(),
        registrationStatus: 'NEW',
      },
    });

    await sendVerificationEmail(email, emailVerifyToken);

    await logAudit({
      userId: user.id,
      action: 'REGISTER',
      entity: 'User',
      entityId: user.id,
      ipAddress: req.ip,
    });

    res.status(201).json({
      message: 'Registrace byla úspěšná. Zkontrolujte svůj e-mail pro ověření.',
      userId: user.id,
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Chyba při registraci.' });
  }
});

// ==================== OVĚŘENÍ E-MAILU ====================
router.get('/verify-email', async (req, res) => {
  const { token } = req.query;
  if (!token) {
    return res.status(400).json({ error: 'Token nebyl poskytnut.' });
  }

  try {
    const user = await prisma.user.findFirst({ where: { emailVerifyToken: token } });
    if (!user) {
      return res.status(404).json({ error: 'Neplatný token.' });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        emailVerifyToken: null,
        registrationStatus: 'PENDING_REVIEW',
      },
    });

    await logAudit({
      userId: user.id,
      action: 'EMAIL_VERIFIED',
      entity: 'User',
      entityId: user.id,
    });

    res.json({ message: 'E-mail byl úspěšně ověřen. Vaše registrace čeká na schválení.' });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ error: 'Chyba při ověřování e-mailu.' });
  }
});

// ==================== PŘIHLÁŠENÍ ====================
router.post('/login', [
  body('email').isEmail().withMessage('Neplatný e-mail.'),
  body('password').notEmpty().withMessage('Heslo je povinné.'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(401).json({ error: 'Neplatné přihlašovací údaje.' });
    }

    // Kontrola zablokování
    if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
      return res.status(423).json({ error: 'Účet je dočasně zablokován. Zkuste to později.' });
    }

    if (user.registrationStatus === 'BLOCKED') {
      return res.status(403).json({ error: 'Váš účet byl zablokován.' });
    }

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) {
      // Zvýšení počtu neúspěšných pokusů
      const attempts = user.failedLoginAttempts + 1;
      const updateData = { failedLoginAttempts: attempts };
      if (attempts >= 5) {
        updateData.lockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minut
      }
      await prisma.user.update({ where: { id: user.id }, data: updateData });
      return res.status(401).json({ error: 'Neplatné přihlašovací údaje.' });
    }

    // Email verification check removed for MVP
    // if (!user.emailVerified) {
    //   return res.status(403).json({ error: 'Nejdříve ověřte svůj e-mail.' });
    // }

    // Reset pokusů, uložení přihlášení
    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: 0,
        lockedUntil: null,
        lastLoginAt: new Date(),
        lastLoginIp: req.ip,
      },
    });

    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    await logAudit({
      userId: user.id,
      action: 'LOGIN',
      entity: 'User',
      entityId: user.id,
      ipAddress: req.ip,
    });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        registrationStatus: user.registrationStatus,
        trustLevel: user.trustLevel,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Chyba při přihlášení.' });
  }
});

// ==================== PROFIL ====================
router.get('/me', authenticate, async (req, res) => {
  const user = req.user;
  res.json({
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    dateOfBirth: user.dateOfBirth,
    addressStreet: user.addressStreet,
    addressCity: user.addressCity,
    addressZip: user.addressZip,
    phone: user.phone,
    isPermanentResident: user.isPermanentResident,
    dateOfBirthChanged: user.dateOfBirthChanged,
    role: user.role,
    registrationStatus: user.registrationStatus,
    trustLevel: user.trustLevel,
    memberSince: user.memberSince,
    emailVerified: user.emailVerified,
    createdAt: user.createdAt,
  });
});

// ==================== ÚPRAVA VLASTNÍHO PROFILU ====================
router.patch('/me', authenticate, async (req, res) => {
  try {
    const b = req.body;
    const data = {};

    // Adresní údaje a telefon - lze měnit volně
    if (b.phone !== undefined) data.phone = b.phone;
    if (b.addressStreet !== undefined) data.addressStreet = b.addressStreet;
    if (b.addressCity !== undefined) data.addressCity = b.addressCity;
    if (b.addressZip !== undefined) data.addressZip = b.addressZip;
    if (b.isPermanentResident !== undefined) data.isPermanentResident = !!b.isPermanentResident;

    // Datum narození - pouze 1x
    if (b.dateOfBirth !== undefined && b.dateOfBirth) {
      if (req.user.dateOfBirthChanged) {
        return res.status(403).json({ error: 'Datum narození už bylo jednou změněno. Další úpravu může provést pouze administrátor.' });
      }
      const newDob = new Date(b.dateOfBirth);
      if (isNaN(newDob.getTime())) {
        return res.status(400).json({ error: 'Neplatné datum narození.' });
      }
      // Kontrola 18 let
      const eighteenYearsAgo = new Date();
      eighteenYearsAgo.setFullYear(eighteenYearsAgo.getFullYear() - 18);
      if (newDob > eighteenYearsAgo) {
        return res.status(400).json({ error: 'Musíte být starší 18 let.' });
      }
      data.dateOfBirth = newDob;
      data.dateOfBirthChanged = true;
    }

    if (Object.keys(data).length === 0) {
      return res.status(400).json({ error: 'Žádná data k uložení.' });
    }

    await prisma.user.update({ where: { id: req.user.id }, data });

    await logAudit({
      userId: req.user.id,
      action: data.dateOfBirthChanged ? 'PROFILE_UPDATED_WITH_DOB' : 'PROFILE_UPDATED',
      entity: 'User',
      entityId: req.user.id,
      ipAddress: req.ip,
    });

    res.json({ message: 'Profil aktualizován.' });
  } catch (error) {
    console.error('Update own profile error:', error);
    res.status(500).json({ error: 'Chyba při ukládání profilu.' });
  }
});

// ==================== ZMĚNA HESLA ====================
router.post('/change-password', authenticate, [
  body('currentPassword').notEmpty().withMessage('Současné heslo je povinné.'),
  body('newPassword').isLength({ min: 8 }).withMessage('Nové heslo musí mít alespoň 8 znaků.'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { currentPassword, newPassword } = req.body;
    const valid = await bcrypt.compare(currentPassword, req.user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: 'Současné heslo je nesprávné.' });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);
    await prisma.user.update({
      where: { id: req.user.id },
      data: { passwordHash },
    });

    await logAudit({
      userId: req.user.id,
      action: 'PASSWORD_CHANGED',
      entity: 'User',
      entityId: req.user.id,
      ipAddress: req.ip,
    });

    res.json({ message: 'Heslo bylo úspěšně změněno.' });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ error: 'Chyba při změně hesla.' });
  }
});

// ==================== ZAPOMENUTÉ HESLO ====================
router.post('/forgot-password', [
  body('email').isEmail().withMessage('Neplatný e-mail.'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.json({ message: 'Pokud účet s tímto e-mailem existuje, odeslali jsme odkaz pro obnovení hesla.' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 60 * 60 * 1000);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordResetToken: resetToken,
        passwordResetExpires: resetExpires,
      },
    });

    await sendPasswordResetEmail(user.email, user.firstName, resetToken);

    await logAudit({
      userId: user.id,
      action: 'PASSWORD_RESET_REQUESTED',
      entity: 'User',
      entityId: user.id,
      ipAddress: req.ip,
    });

    res.json({ message: 'Pokud účet s tímto e-mailem existuje, odeslali jsme odkaz pro obnovení hesla.' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Chyba při zpracování žádosti.' });
  }
});

// ==================== RESET HESLA ====================
router.post('/reset-password', [
  body('token').notEmpty().withMessage('Token je povinný.'),
  body('newPassword').isLength({ min: 8 }).withMessage('Nové heslo musí mít alespoň 8 znaků.'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { token, newPassword } = req.body;

    const user = await prisma.user.findFirst({
      where: {
        passwordResetToken: token,
        passwordResetExpires: { gt: new Date() },
      },
    });

    if (!user) {
      return res.status(400).json({ error: 'Neplatný nebo vypršený token pro obnovení hesla.' });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash,
        passwordResetToken: null,
        passwordResetExpires: null,
        failedLoginAttempts: 0,
        lockedUntil: null,
      },
    });

    await logAudit({
      userId: user.id,
      action: 'PASSWORD_RESET',
      entity: 'User',
      entityId: user.id,
      ipAddress: req.ip,
    });

    res.json({ message: 'Heslo bylo úspěšně obnoveno. Nyní se můžete přihlásit.' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Chyba při obnovení hesla.' });
  }
});

module.exports = router;
