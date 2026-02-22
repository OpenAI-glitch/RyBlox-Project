const mongoose = require('mongoose');

const BrickSchema = new mongoose.Schema({
  id: { type: String, required: true },
  shape: { type: String, enum: ['Block', 'Wedge', 'Cylinder', 'Ball'], default: 'Block' },
  position: {
    x: { type: Number, default: 0 },
    y: { type: Number, default: 0 },
    z: { type: Number, default: 0 }
  },
  rotation: {
    x: { type: Number, default: 0 },
    y: { type: Number, default: 0 },
    z: { type: Number, default: 0 }
  },
  scale: {
    x: { type: Number, default: 1 },
    y: { type: Number, default: 1 },
    z: { type: Number, default: 1 }
  },
  color: { type: String, default: '#4A90D9' },
  transparency: { type: Number, default: 0, min: 0, max: 1 },
  reflectance: { type: Number, default: 0, min: 0, max: 1 }
});

const WorldSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  description: { type: String, default: '', maxlength: 500 },
  creatorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  creatorName: { type: String, required: true },
  isPublic: { type: Boolean, default: true },
  thumbnailUrl: { type: String, default: '' },
  bricks: [BrickSchema],
  maxPlayers: { type: Number, default: 10, min: 1, max: 100 },
  visits: { type: Number, default: 0 },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  tags: [{ type: String }],
  ambient: { type: String, default: '#87CEEB' },
  skyColor: { type: String, default: '#87CEEB' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

module.exports = mongoose.model('World', WorldSchema);
