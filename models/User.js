const mongoose = require('mongoose');

const TransactionSchema = new mongoose.Schema({
  type: { type: String, enum: ['earn', 'spend', 'transfer_in', 'transfer_out', 'daily'], required: true },
  amount: { type: Number, required: true },
  description: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

const WallPostSchema = new mongoose.Schema({
  authorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  authorName: { type: String, required: true },
  content: { type: String, required: true, maxlength: 500 },
  createdAt: { type: Date, default: Date.now }
});

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 20,
    match: /^[a-zA-Z0-9_]+$/
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  },
  passwordHash: { type: String, required: true },
  rank: { type: String, enum: ['Membre', 'Staff', 'Admin'], default: 'Membre' },
  rycredits: { type: Number, default: 100 },
  lastDailyReward: { type: Date, default: null },
  transactions: [TransactionSchema],
  inventory: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Item' }],
  avatar: {
    headColor:   { type: String, default: '#F5C89A' },
    torsoColor:  { type: String, default: '#1A73E8' },
    leftArmColor:  { type: String, default: '#F5C89A' },
    rightArmColor: { type: String, default: '#F5C89A' },
    leftLegColor:  { type: String, default: '#2C2C2C' },
    rightLegColor: { type: String, default: '#2C2C2C' },
    equippedItems: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Item' }],
    rigType: { type: String, enum: ['R6', 'R15'], default: 'R6' }
  },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  friendRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  wallPosts: [WallPostSchema],
  bio: { type: String, default: '', maxlength: 200 },
  isOnline: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);
