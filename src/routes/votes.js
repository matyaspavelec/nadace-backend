const express = require('express');
const { body, validationResult } = require('express-validator');
const prisma = require('../prisma');
const { authenticate, requireApproved } = require('../middleware/auth');
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

module.exports = router;
