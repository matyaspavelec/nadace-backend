const express = require('express');
const { body, validationResult } = require('express-validator');
const prisma = require('../prisma');
const { authenticate, requireApproved, requireRole } = require('../middleware/auth');
const { logAudit } = require('../utils/audit');
const logger = require('../utils/logger');

const router = express.Router();

// ==================== HLASOVAT ====================
router.post('/', authenticate, requireApproved, [
  body('projectId').notEmpty().withMessage('ID projektu je povinné.'),
  body('value').isIn(['YES', 'NO']).withMessage('Hlas musí být YES nebo NO.'),
  body('comment').optional().trim(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { projectId, value, comment } = req.body;

    // Ověření, že projekt je v hlasování
    const project = await prisma.project.findUnique({ where: { id: projectId } });
    if (!project) return res.status(404).json({ error: 'Projekt nenalezen.' });
    if (project.status !== 'PUBLISHED_FOR_VOTING') {
      return res.status(400).json({ error: 'Tento projekt není otevřen pro hlasování.' });
    }

    // Kontrola termínu hlasování
    const now = new Date();
    if (project.votingEndDate && now > new Date(project.votingEndDate)) {
      return res.status(400).json({ error: 'Hlasování pro tento projekt již skončilo.' });
    }

    // Zkontrolovat, jestli uživatel už hlasoval – hlas je konečný
    const existingVote = await prisma.vote.findUnique({
      where: { userId_projectId: { userId: req.user.id, projectId } },
    });

    if (existingVote) {
      return res.status(409).json({ error: 'Pro tento projekt jste již hlasoval/a. Hlas nelze změnit.' });
    }

    // Nový hlas
    const vote = await prisma.vote.create({
      data: {
        userId: req.user.id,
        projectId,
        value,
        comment: comment || null,
      },
    });

    // Aktualizace počítadel
    const updateData = value === 'YES'
      ? { votesFor: { increment: 1 } }
      : { votesAgainst: { increment: 1 } };
    await prisma.project.update({ where: { id: projectId }, data: updateData });

    await logAudit({
      userId: req.user.id,
      action: 'VOTE_CAST',
      entity: 'Vote',
      entityId: vote.id,
      details: value,
      ipAddress: req.ip,
    });

    res.status(201).json({ message: 'Hlas byl zaznamenán.', vote });
  } catch (error) {
    logger.error({ err: error }, 'Vote error');
    res.status(500).json({ error: 'Chyba při hlasování.' });
  }
});

// ==================== MŮJHLAS PRO PROJEKT ====================
router.get('/my/:projectId', authenticate, async (req, res) => {
  try {
    const vote = await prisma.vote.findUnique({
      where: { userId_projectId: { userId: req.user.id, projectId: req.params.projectId } },
    });
    res.json({ vote: vote || null });
  } catch (error) {
    logger.error({ err: error }, 'My vote error');
    res.status(500).json({ error: 'Chyba při načítání hlasu.' });
  }
});

// ==================== VÝSLEDKY HLASOVÁNÍ (admin) ====================
router.get('/results/:projectId', authenticate, async (req, res) => {
  try {
    const project = await prisma.project.findUnique({
      where: { id: req.params.projectId },
      select: { id: true, title: true, votesFor: true, votesAgainst: true, status: true, votingStartDate: true, votingEndDate: true },
    });

    if (!project) return res.status(404).json({ error: 'Projekt nenalezen.' });

    const totalVotes = project.votesFor + project.votesAgainst;

    res.json({
      ...project,
      totalVotes,
      approvalRate: totalVotes > 0 ? ((project.votesFor / totalVotes) * 100).toFixed(1) : 0,
    });
  } catch (error) {
    logger.error({ err: error }, 'Vote results error');
    res.status(500).json({ error: 'Chyba při načítání výsledků.' });
  }
});

// ==================== SEZNAM VOLIČŮ U PROJEKTU (admin) ====================
router.get('/project/:projectId/voters', authenticate, requireRole('ADMIN'), async (req, res) => {
  try {
    const { projectId } = req.params;
    const project = await prisma.project.findUnique({ where: { id: projectId } });
    if (!project) return res.status(404).json({ error: 'Projekt nenalezen.' });

    const voters = await prisma.vote.findMany({
      where: { projectId },
      include: {
        user: { select: { id: true, firstName: true, lastName: true, email: true } },
      },
      orderBy: { createdAt: 'desc' },
    });

    res.json({ voters });
  } catch (error) {
    logger.error({ err: error }, 'Voters list error');
    res.status(500).json({ error: 'Chyba při načítání voličů.' });
  }
});

// ==================== SMAZAT JEDEN HLAS (admin) ====================
// Použití: uživatel kontaktuje nadaci a žádá o opravu překlepu; admin
// smaže jeho hlas, čímž mu umožní znovu hlasovat.
router.delete('/:voteId', authenticate, requireRole('ADMIN'), async (req, res) => {
  try {
    const { voteId } = req.params;
    const vote = await prisma.vote.findUnique({
      where: { id: voteId },
      include: { user: { select: { email: true } } },
    });
    if (!vote) return res.status(404).json({ error: 'Hlas nenalezen.' });

    await prisma.$transaction(async (tx) => {
      await tx.vote.delete({ where: { id: voteId } });
      await tx.project.update({
        where: { id: vote.projectId },
        data: vote.value === 'YES'
          ? { votesFor: { decrement: 1 } }
          : { votesAgainst: { decrement: 1 } },
      });
    });

    await logAudit({
      userId: req.user.id,
      action: 'VOTE_DELETED_BY_ADMIN',
      entity: 'Vote',
      entityId: voteId,
      details: `Smazán hlas ${vote.value} uživatele ${vote.user?.email || vote.userId} (projekt ${vote.projectId})`,
      ipAddress: req.ip,
    });

    res.json({ message: 'Hlas byl smazán. Uživatel může znovu hlasovat.' });
  } catch (error) {
    logger.error({ err: error }, 'Delete vote error');
    res.status(500).json({ error: 'Chyba při mazání hlasu.' });
  }
});

// ==================== RESTART HLASOVÁNÍ (admin) ====================
// Smaže všechny hlasy a vynuluje počítadla. Pokud jsou zadány datumy,
// nastaví nové okno hlasování a status na PUBLISHED_FOR_VOTING; jinak
// zůstane status i datumy beze změny (čistý wipe).
router.post('/project/:projectId/restart', authenticate, requireRole('ADMIN'), [
  body('votingStartDate').optional({ checkFalsy: true }).isISO8601().withMessage('Neplatný formát začátku hlasování.'),
  body('votingEndDate').optional({ checkFalsy: true }).isISO8601().withMessage('Neplatný formát konce hlasování.'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { projectId } = req.params;
    const { votingStartDate, votingEndDate } = req.body;

    const project = await prisma.project.findUnique({ where: { id: projectId } });
    if (!project) return res.status(404).json({ error: 'Projekt nenalezen.' });

    if (votingStartDate && votingEndDate && new Date(votingEndDate) <= new Date(votingStartDate)) {
      return res.status(400).json({ error: 'Konec hlasování musí být po jeho začátku.' });
    }

    const hasNewWindow = !!(votingStartDate || votingEndDate);

    const result = await prisma.$transaction(async (tx) => {
      const deleted = await tx.vote.deleteMany({ where: { projectId } });
      await tx.project.update({
        where: { id: projectId },
        data: {
          votesFor: 0,
          votesAgainst: 0,
          ...(hasNewWindow ? { status: 'PUBLISHED_FOR_VOTING' } : {}),
          ...(votingStartDate ? { votingStartDate: new Date(votingStartDate) } : {}),
          ...(votingEndDate ? { votingEndDate: new Date(votingEndDate) } : {}),
        },
      });
      return deleted.count;
    });

    await logAudit({
      userId: req.user.id,
      action: 'VOTES_RESTARTED',
      entity: 'Project',
      entityId: projectId,
      details: `Smazáno ${result} hlasů${hasNewWindow ? `, nové okno: ${votingStartDate || 'beze změny'} – ${votingEndDate || 'beze změny'}` : ' (beze změny okna)'}`,
      ipAddress: req.ip,
    });

    res.json({
      message: hasNewWindow
        ? `Hlasování bylo restartováno. Smazáno ${result} hlasů.`
        : `Hlasy byly vynulovány. Smazáno ${result} hlasů.`,
      deletedCount: result,
    });
  } catch (error) {
    logger.error({ err: error }, 'Restart votes error');
    res.status(500).json({ error: 'Chyba při restartu hlasování.' });
  }
});

module.exports = router;
