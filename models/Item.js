const mongoose = require('mongoose');

const ItemSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  description: { type: String, default: '', maxlength: 500 },
  type: {
    type: String,
    enum: ['hat', 'texture_shirt', 'texture_pants', 'face', 'accessory'],
    required: true
  },
  creatorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  creatorName: { type: String, required: true },
  price: { type: Number, default: 0, min: 0 },
  isFree: { type: Boolean, default: false },
  isApproved: { type: Boolean, default: false }, // modération staff
  fileUrl: { type: String, required: true },   // URL fichier OBJ ou PNG
  thumbnailUrl: { type: String, default: '' },
  tags: [{ type: String }],
  purchases: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

module.exports = mongoose.model('Item', ItemSchema);
