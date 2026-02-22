// ============================================================
//  RYBLOX — index.js  (Node.js / Express backend)
//  Stack : Express + Mongoose + JWT + Bcrypt
//  v2 : Détection automatique Admin Master + middlewares de rang
// ============================================================
require('dotenv').config();

const express   = require('express');
const mongoose  = require('mongoose');
const bcrypt    = require('bcrypt');
const jwt       = require('jsonwebtoken');
const path      = require('path');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');

const User  = require('./models/User');
const Item  = require('./models/Item');
const World = require('./models/World');

const app = express();

// ── Vérification des variables critiques au démarrage ────────
const JWT_SECRET  = process.env.JWT_SECRET;
const JWT_EXPIRES = process.env.JWT_EXPIRES || '7d';

if (!JWT_SECRET) {
  console.error('❌  FATAL : JWT_SECRET manquant dans .env — arrêt du serveur.');
  process.exit(1);
}

// Lire les identifiants Master depuis .env
const ADMIN_MASTER_USERNAME = process.env.ADMIN_MASTER_USERNAME?.trim()         || null;
const ADMIN_MASTER_EMAIL    = process.env.ADMIN_MASTER_EMAIL?.toLowerCase().trim() || null;

if (ADMIN_MASTER_USERNAME && ADMIN_MASTER_EMAIL) {
  console.log(`🛡️  Admin Master configuré : @${ADMIN_MASTER_USERNAME} <${ADMIN_MASTER_EMAIL}>`);
} else {
  console.warn('⚠️  ADMIN_MASTER_USERNAME / ADMIN_MASTER_EMAIL non définis dans .env');
}

// ── Middleware globaux ────────────────────────────────────────
app.use(cors({ origin: process.env.CLIENT_ORIGIN || '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiter — anti-brute-force sur les routes auth
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Trop de tentatives, réessaie dans 15 minutes.' }
});

// ── Connexion MongoDB ─────────────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/ryblox', {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => console.log('✅  MongoDB connecté'))
  .catch(err => { console.error('❌  MongoDB :', err.message); process.exit(1); });

// ── Helper : détection rang à l'inscription ──────────────────
/**
 * Détermine automatiquement le rang d'un nouvel utilisateur.
 * Si le username OU l'email correspond aux variables Master dans .env,
 * le rang 'Admin' est attribué sans intervention manuelle.
 *
 * @param {string} username - Nom d'utilisateur saisi
 * @param {string} email    - Email saisi (déjà en lowercase)
 * @returns {'Admin'|'Membre'}
 */
function resolveInitialRank(username, email) {
  if (!ADMIN_MASTER_USERNAME || !ADMIN_MASTER_EMAIL) return 'Membre';

  const isMaster =
    username === ADMIN_MASTER_USERNAME ||
    email    === ADMIN_MASTER_EMAIL;

  if (isMaster) {
    console.log(`[SYSTEM] ✅  Attribution automatique du rang Admin à : ${username} (${email})`);
    return 'Admin';
  }
  return 'Membre';
}

// ── Helper JWT ────────────────────────────────────────────────
/**
 * Signe un token JWT contenant l'id ET le rang de l'utilisateur.
 * Le rang dans le token évite une requête DB à chaque middleware.
 */
function signToken(userId, rank) {
  return jwt.sign({ id: userId, rank }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

// ─────────────────────────────────────────────────────────────
//  MIDDLEWARES DE PROTECTION PAR RANG
// ─────────────────────────────────────────────────────────────

/**
 * authenticate — Vérifie le JWT et injecte userId + userRank dans req.
 * À utiliser sur toutes les routes nécessitant une connexion.
 */
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Token manquant.' });
  }
  try {
    const payload = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    req.userId   = payload.id;
    req.userRank = payload.rank; // 'Membre' | 'Staff' | 'Admin'
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Token invalide ou expiré.' });
  }
}

/**
 * checkAdmin — Réserve la route aux Admins uniquement.
 * Doit être placé APRÈS authenticate.
 *
 * Usage : app.delete('/api/items/:id', authenticate, checkAdmin, handler);
 */
function checkAdmin(req, res, next) {
  if (req.userRank !== 'Admin') {
    return res.status(403).json({
      success: false,
      message: 'Accès refusé : Droits Admin requis.'
    });
  }
  next();
}

/**
 * checkStaff — Réserve la route aux Staff ET aux Admins.
 * Doit être placé APRÈS authenticate.
 *
 * Usage : app.patch('/api/items/:id/approve', authenticate, checkStaff, handler);
 */
function checkStaff(req, res, next) {
  if (req.userRank !== 'Staff' && req.userRank !== 'Admin') {
    return res.status(403).json({
      success: false,
      message: 'Accès refusé : Droits Staff ou Admin requis.'
    });
  }
  next();
}

// ─────────────────────────────────────────────────────────────
//  ROUTES AUTH
// ─────────────────────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // ── Validation des champs ──────────────────────────────────
    if (!username || !email || !password) {
      return res.status(400).json({ success: false, message: 'Tous les champs sont requis.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ success: false, message: 'Mot de passe trop court (min 8 caractères).' });
    }
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({ success: false, message: "Nom d'utilisateur invalide (3-20 caractères, lettres/chiffres/_)." });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // ── Unicité username + email ───────────────────────────────
    const exists = await User.findOne({
      $or: [{ email: normalizedEmail }, { username }]
    });
    if (exists) {
      const field = exists.email === normalizedEmail ? 'email' : "nom d'utilisateur";
      return res.status(409).json({ success: false, message: `Ce ${field} est déjà utilisé.` });
    }

    // ── Détection automatique du rang Admin Master ─────────────
    const masterUsername = process.env.ADMIN_MASTER_USERNAME;
    const masterEmail    = process.env.ADMIN_MASTER_EMAIL;
    let finalRank = 'Membre';
    if (username === masterUsername || normalizedEmail === masterEmail) {
      finalRank = 'Admin';
      console.log(`[SYSTEM] Attribution automatique du rang Admin à : ${username}`);
    }

    // ── Création du compte ─────────────────────────────────────
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({
      username,
      email:        normalizedEmail,
      passwordHash,
      rank:         finalRank
    });

    const token = signToken(user._id, user.rank);

    res.status(201).json({
      success: true,
      message: finalRank === 'Admin'
        ? `Bienvenue, Administrateur ${username} ! 🛡️`
        : 'Compte créé avec succès !',
      token,
      user: {
        id:        user._id,
        username:  user.username,
        rank:      user.rank,
        rycredits: user.rycredits
      }
    });

  } catch (err) {
    console.error('[register]', err);
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Tous les champs sont requis.' });
    }

    // Accepte username ou email
    const user = await User.findOne({
      $or: [{ username }, { email: username.toLowerCase().trim() }]
    });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Identifiants invalides.' });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res.status(401).json({ success: false, message: 'Identifiants invalides.' });
    }

    user.isOnline = true;
    await user.save();

    // Le rang est toujours relu depuis la DB à la connexion (jamais périmé)
    const token = signToken(user._id, user.rank);

    res.json({
      success: true,
      message: 'Connexion réussie !',
      token,
      user: {
        id:        user._id,
        username:  user.username,
        rank:      user.rank,
        rycredits: user.rycredits
      }
    });

  } catch (err) {
    console.error('[login]', err);
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', authenticate, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.userId, { isOnline: false });
    res.json({ success: true, message: 'Déconnecté.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// ─────────────────────────────────────────────────────────────
//  ROUTES USER
// ─────────────────────────────────────────────────────────────

// GET /api/users/me — profil connecté complet
app.get('/api/users/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId)
      .select('-passwordHash')
      .populate('inventory', 'name type thumbnailUrl')
      .populate('avatar.equippedItems', 'name type fileUrl');
    if (!user) return res.status(404).json({ success: false, message: 'Utilisateur introuvable.' });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// GET /api/users/:username — profil public
app.get('/api/users/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username })
      .select('-passwordHash -email -transactions -friendRequests')
      .populate('inventory', 'name type thumbnailUrl')
      .populate('avatar.equippedItems', 'name type fileUrl');
    if (!user) return res.status(404).json({ success: false, message: 'Utilisateur introuvable.' });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// POST /api/users/daily — récompense quotidienne
app.post('/api/users/daily', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const now  = new Date();
    const last = user.lastDailyReward;

    if (last) {
      const diffMs = now - last;
      if (diffMs < 24 * 3600 * 1000) {
        const nextMs = 24 * 3600 * 1000 - diffMs;
        const nextH  = Math.floor(nextMs / 3600000);
        const nextM  = Math.floor((nextMs % 3600000) / 60000);
        return res.status(429).json({
          success: false,
          message: `Déjà réclamé ! Reviens dans ${nextH}h ${nextM}min.`
        });
      }
    }

    const reward = 50;
    user.rycredits += reward;
    user.lastDailyReward = now;
    user.transactions.push({ type: 'daily', amount: reward, description: 'Récompense quotidienne' });
    await user.save();

    res.json({ success: true, message: `+${reward} Rycredits !`, rycredits: user.rycredits });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// ─────────────────────────────────────────────────────────────
//  ROUTES ADMIN (authenticate + checkAdmin requis)
// ─────────────────────────────────────────────────────────────

// GET /api/admin/users — liste tous les comptes
app.get('/api/admin/users', authenticate, checkAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const users = await User.find()
      .select('username email rank rycredits isOnline createdAt')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit));
    const total = await User.countDocuments();
    res.json({ success: true, users, total });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// PATCH /api/admin/users/:id/rank — modifier le rang d'un utilisateur
app.patch('/api/admin/users/:id/rank', authenticate, checkAdmin, async (req, res) => {
  try {
    const { rank } = req.body;
    if (!['Membre', 'Staff', 'Admin'].includes(rank)) {
      return res.status(400).json({ success: false, message: 'Rang invalide.' });
    }
    const target = await User.findByIdAndUpdate(
      req.params.id,
      { rank },
      { new: true }
    ).select('username rank');
    if (!target) return res.status(404).json({ success: false, message: 'Utilisateur introuvable.' });
    console.log(`[ADMIN] Rang de @${target.username} mis à jour → ${rank}`);
    res.json({ success: true, message: `Rang mis à jour → ${rank}`, user: target });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// DELETE /api/admin/users/:id — supprimer un compte
app.delete('/api/admin/users/:id', authenticate, checkAdmin, async (req, res) => {
  try {
    if (req.params.id === req.userId) {
      return res.status(400).json({ success: false, message: 'Vous ne pouvez pas supprimer votre propre compte Admin.' });
    }
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Compte supprimé.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// ─────────────────────────────────────────────────────────────
//  ROUTES STAFF (authenticate + checkStaff requis)
// ─────────────────────────────────────────────────────────────

// GET /api/staff/items/pending — items en attente de modération
app.get('/api/staff/items/pending', authenticate, checkStaff, async (req, res) => {
  try {
    const items = await Item.find({ isApproved: false })
      .select('name type price creatorName fileUrl createdAt')
      .sort({ createdAt: 1 });
    res.json({ success: true, items, count: items.length });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// PATCH /api/staff/items/:id/approve — approuver un item
app.patch('/api/staff/items/:id/approve', authenticate, checkStaff, async (req, res) => {
  try {
    const item = await Item.findByIdAndUpdate(
      req.params.id,
      { isApproved: true },
      { new: true }
    ).select('name type isApproved');
    if (!item) return res.status(404).json({ success: false, message: 'Item introuvable.' });
    res.json({ success: true, message: `Item "${item.name}" approuvé.`, item });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// PATCH /api/staff/items/:id/reject — refuser un item
app.patch('/api/staff/items/:id/reject', authenticate, checkStaff, async (req, res) => {
  try {
    const item = await Item.findByIdAndUpdate(
      req.params.id,
      { isApproved: false },
      { new: true }
    ).select('name isApproved');
    if (!item) return res.status(404).json({ success: false, message: 'Item introuvable.' });
    res.json({ success: true, message: `Item "${item.name}" refusé.` });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// ─────────────────────────────────────────────────────────────
//  ROUTES WORLDS
// ─────────────────────────────────────────────────────────────

// GET /api/worlds — liste des mondes publics
app.get('/api/worlds', async (req, res) => {
  try {
    const worlds = await World.find({ isPublic: true })
      .select('name description creatorName thumbnailUrl visits likes tags createdAt')
      .sort({ visits: -1 })
      .limit(20);
    res.json({ success: true, worlds });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// GET /api/worlds/:id — monde complet pour le moteur 3D
app.get('/api/worlds/:id', async (req, res) => {
  try {
    const world = await World.findById(req.params.id);
    if (!world || !world.isPublic) {
      return res.status(404).json({ success: false, message: 'Monde introuvable.' });
    }
    world.visits += 1;
    await world.save();
    res.json({ success: true, world });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// POST /api/worlds — créer un monde
app.post('/api/worlds', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const { name, description, isPublic, maxPlayers } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Nom requis.' });

    const world = await World.create({
      name,
      description,
      isPublic:    isPublic !== false,
      maxPlayers:  maxPlayers || 10,
      creatorId:   user._id,
      creatorName: user.username,
      bricks: []
    });
    res.status(201).json({ success: true, world });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// PUT /api/worlds/:id/bricks — sauvegarder les briques du studio
app.put('/api/worlds/:id/bricks', authenticate, async (req, res) => {
  try {
    const world = await World.findById(req.params.id);
    if (!world) return res.status(404).json({ success: false, message: 'Monde introuvable.' });

    // Créateur OU Admin peuvent sauvegarder
    if (String(world.creatorId) !== req.userId && req.userRank !== 'Admin') {
      return res.status(403).json({ success: false, message: 'Accès refusé.' });
    }

    world.bricks    = req.body.bricks || [];
    world.updatedAt = new Date();
    await world.save();
    res.json({ success: true, message: 'Monde sauvegardé.', brickCount: world.bricks.length });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// DELETE /api/worlds/:id — supprimer un monde
app.delete('/api/worlds/:id', authenticate, async (req, res) => {
  try {
    const world = await World.findById(req.params.id);
    if (!world) return res.status(404).json({ success: false, message: 'Monde introuvable.' });

    if (String(world.creatorId) !== req.userId && req.userRank !== 'Admin') {
      return res.status(403).json({ success: false, message: 'Accès refusé.' });
    }
    await world.deleteOne();
    res.json({ success: true, message: 'Monde supprimé.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// ─────────────────────────────────────────────────────────────
//  ROUTES CATALOGUE
// ─────────────────────────────────────────────────────────────

// GET /api/items — catalogue public approuvé
app.get('/api/items', async (req, res) => {
  try {
    const { type, page = 1, limit = 24 } = req.query;
    const filter = { isApproved: true };
    if (type) filter.type = type;
    const items = await Item.find(filter)
      .select('name type price isFree thumbnailUrl creatorName purchases')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit));
    res.json({ success: true, items });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// POST /api/items/:id/buy — acheter un item
app.post('/api/items/:id/buy', authenticate, async (req, res) => {
  try {
    const [user, item] = await Promise.all([
      User.findById(req.userId),
      Item.findById(req.params.id)
    ]);
    if (!item || !item.isApproved) {
      return res.status(404).json({ success: false, message: 'Item introuvable.' });
    }
    if (user.inventory.some(id => String(id) === String(item._id))) {
      return res.status(409).json({ success: false, message: 'Item déjà possédé.' });
    }
    const cost = item.isFree ? 0 : item.price;
    if (user.rycredits < cost) {
      return res.status(402).json({ success: false, message: 'Rycredits insuffisants.' });
    }
    user.rycredits -= cost;
    user.inventory.push(item._id);
    user.transactions.push({ type: 'spend', amount: cost, description: `Achat: ${item.name}` });
    item.purchases += 1;
    await Promise.all([user.save(), item.save()]);
    res.json({ success: true, message: 'Achat réussi !', rycredits: user.rycredits });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// ── Wildcard → index.html (SPA fallback) ─────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Démarrage ─────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀  Ryblox server → http://localhost:${PORT}`)
);
