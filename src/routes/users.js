const express = require('express');
const prisma = require('../prisma');
const { authenticate, requireRole } = require('../middleware/auth');
const { logAudit } = require('../utils/audit');
const { sendStatusChangeEmail } = require('../utils/email');

const router = express.Router();

// ==================== SEZNAM UŽIVATELŮ (admin) ====================
router.get('/', authenticate, requireRole('ADMIN', 'REGISTRATION_MANAGER'), async (req, res) => {
  try {
    const { status, search, page = 1, limit = 20 } = req.query;
    const where = {};

    if (status) where.registrationStatus = status;
    if (search) {
      where.OR = [
        { firstName: { contains: search } },
        { lastName: { contains: search } },
        { email: { contains: search } },
      ];
    }

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        select: {
          id: true, email: true, firstName: true, lastName: true,
          phone: true, addressCity: true, isPermanentResident: true,
          registrationStatus: true, trustLevel: true, role: true,
          memberSince: true, emailVerified: true, createdAt: true,
          internalNote: true, approvalNote: true, rejectionReason: true,
        },
        orderBy: { createdAt: 'desc' },
        skip: (parseInt(page) - 1) * parseInt(limit),
        take: parseInt(limit),
      }),
      prisma.user.count({ where }),
    ]);

    res.json({ users, total, page: parseInt(page), totalPages: Math.ceil(total / parseInt(limit)) });
  } catch (error) {
    console.error('List users error:', error);
    res.status(500).json({ error: 'Chyba při načítání uživatelů.' });
  }
});

// ==================== DETAIL UŽIVATELE (admin) ====================
router.get('/:id', authenticate, requireRole('ADMIN', 'REGISTRATION_MANAGER'), async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.params.id },
      include: {
        interviews: { orderBy: { scheduledDate: 'desc' } },
        projects: { select: { id: true, title: true, status: true, createdAt: true } },
        approvedBy: { select: { id: true, firstName: true, lastName: true } },
      },
    });

    if (!user) return res.status(404).json({ error: 'Uživatel nenalezen.' });

    const { passwordHash, twoFactorSecret, emailVerifyToken, ...safeUser } = user;
    res.json(safeUser);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Chyba při načítání uživatele.' });
  }
});

// ==================== ZMĚNA STAVU REGISTRACE ====================
router.patch('/:id/status', authenticate, requireRole('ADMIN', 'REGISTRATION_MANAGER'), async (req, res) => {
  try {
    const { status, note } = req.body;
    const validStatuses = ['NEW', 'PENDING_REVIEW', 'INVITED_FOR_INTERVIEW', 'APPROVED', 'REJECTED', 'BLOCKED'];

    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Neplatný stav registrace.' });
    }

    const user = await prisma.user.findUnique({ where: { id: req.params.id } });
    if (!user) return res.status(404).json({ error: 'Uživatel nenalezen.' });

    const updateData = {
      registrationStatus: status,
      approvedById: req.user.id,
    };

    if (status === 'APPROVED') {
      updateData.approvalDate = new Date();
      updateData.approvalNote = note || null;
      updateData.memberSince = new Date();
    } else if (status === 'REJECTED') {
      updateData.rejectionReason = note || null;
    } else if (status === 'BLOCKED') {
      updateData.approvalNote = note || null;
    }

    const updated = await prisma.user.update({
      where: { id: req.params.id },
      data: updateData,
    });

    await logAudit({
      userId: req.params.id,
      adminId: req.user.id,
      action: `STATUS_CHANGED_TO_${status}`,
      entity: 'User',
      entityId: req.params.id,
      details: note || null,
      ipAddress: req.ip,
    });

    await sendStatusChangeEmail(updated.email, updated.firstName, status, note);

    res.json({ message: `Stav uživatele změněn na ${status}.`, user: { id: updated.id, registrationStatus: updated.registrationStatus } });
  } catch (error) {
    console.error('Status change error:', error);
    res.status(500).json({ error: 'Chyba při změně stavu.' });
  }
});

// ==================== ZMĚNA ROLE ====================
router.patch('/:id/role', authenticate, requireRole('ADMIN'), async (req, res) => {
  try {
    const { role } = req.body;
    const validRoles = ['USER', 'REGISTRATION_MANAGER', 'PROJECT_REVIEWER', 'CONTENT_EDITOR', 'COMMENT_MODERATOR', 'ADMIN'];

    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: 'Neplatná role.' });
    }

    await prisma.user.update({ where: { id: req.params.id }, data: { role } });

    await logAudit({
      userId: req.params.id,
      adminId: req.user.id,
      action: `ROLE_CHANGED_TO_${role}`,
      entity: 'User',
      entityId: req.params.id,
      ipAddress: req.ip,
    });

    res.json({ message: `Role uživatele změněna na ${role}.` });
  } catch (error) {
    console.error('Role change error:', error);
    res.status(500).json({ error: 'Chyba při změně role.' });
  }
});

// ==================== ÚPRAVA OSOBNÍCH ÚDAJŮ (admin) ====================
router.patch('/:id/profile', authenticate, requireRole('ADMIN', 'REGISTRATION_MANAGER'), async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.params.id } });
    if (!user) return res.status(404).json({ error: 'Uživatel nenalezen.' });

    const b = req.body;
    const data = {};
    if (b.firstName !== undefined) data.firstName = b.firstName;
    if (b.lastName !== undefined) data.lastName = b.lastName;
    if (b.email !== undefined) data.email = b.email;
    if (b.phone !== undefined) data.phone = b.phone;
    if (b.dateOfBirth !== undefined) data.dateOfBirth = b.dateOfBirth ? new Date(b.dateOfBirth) : null;
    if (b.resetDobLock) data.dateOfBirthChanged = false;
    if (b.addressStreet !== undefined) data.addressStreet = b.addressStreet;
    if (b.addressCity !== undefined) data.addressCity = b.addressCity;
    if (b.addressZip !== undefined) data.addressZip = b.addressZip;
    if (b.isPermanentResident !== undefined) data.isPermanentResident = !!b.isPermanentResident;

    const updated = await prisma.user.update({ where: { id: req.params.id }, data });

    await logAudit({
      userId: req.params.id,
      adminId: req.user.id,
      action: 'USER_PROFILE_UPDATED',
      entity: 'User',
      entityId: req.params.id,
      ipAddress: req.ip,
    });

    res.json({ message: 'Osobní údaje uživatele aktualizovány.', user: { id: updated.id } });
  } catch (error) {
    console.error('Update user profile error:', error);
    res.status(500).json({ error: 'Chyba při ukládání osobních údajů.' });
  }
});

// ==================== INTERNÍ HODNOCENÍ ====================
router.patch('/:id/trust', authenticate, requireRole('ADMIN', 'REGISTRATION_MANAGER'), async (req, res) => {
  try {
    const { trustLevel, internalNote } = req.body;
    const validLevels = ['NEW_MEMBER', 'ACTIVE_BENEFICIAL', 'UNPROBLEMATIC', 'CONFLICTING', 'COMMENT_RESTRICTED'];

    if (!validLevels.includes(trustLevel)) {
      return res.status(400).json({ error: 'Neplatná úroveň důvěryhodnosti.' });
    }

    await prisma.user.update({
      where: { id: req.params.id },
      data: { trustLevel, internalNote: internalNote || undefined },
    });

    await logAudit({
      userId: req.params.id,
      adminId: req.user.id,
      action: `TRUST_LEVEL_CHANGED_TO_${trustLevel}`,
      entity: 'User',
      entityId: req.params.id,
      details: internalNote || null,
      ipAddress: req.ip,
    });

    res.json({ message: 'Hodnocení důvěryhodnosti aktualizováno.' });
  } catch (error) {
    console.error('Trust level change error:', error);
    res.status(500).json({ error: 'Chyba při změně hodnocení.' });
  }
});

module.exports = router;
