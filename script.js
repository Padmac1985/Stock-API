
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');


const app = express();
app.use(cors());
app.use(bodyParser.json());


// Basic rate limiter for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 20,
  message: 'Too many attempts, please try again later',
});
app.use('/api/auth/', authLimiter);


mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});


// MongoDB models
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  groupId: String,
  creditScore: { type: Number, default: 600 },
  nftBadge: String,
}));


const Group = mongoose.model('Group', new mongoose.Schema({
  name: String,
  members: [String],
  trustScore: { type: Number, default: 100 },
  insurancePool: { type: Number, default: 0 },
}));


const Portfolio = mongoose.model('Portfolio', new mongoose.Schema({
  userId: String,
  stocks: [{ symbol: String, quantity: Number, marketPrice: Number }],
}));


const Loan = mongoose.model('Loan', new mongoose.Schema({
  userId: String,
  amount: Number,
  approved: Boolean,
  repaid: { type: Boolean, default: false },
  reason: String,
}));


// Auth middleware
const authMiddleware = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Missing token' });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = decoded;
    next();
  });
};


// Auth routes
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    await new User({ name, email, password: hashed }).save();
    res.json({ message: 'Registered' });
  } catch (err) {
    res.status(400)
       .json({ message: err.code === 11000 ? 'Email already used' : 'Registration failed' });
  }
});


app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ message: 'Invalid credentials' });


  const token = jwt.sign({ id: user._id, name: user.name }, process.env.JWT_SECRET, {
    expiresIn: '1h'
  });
  res.json({ token });
});


// User profile
app.get('/api/user/profile', authMiddleware, async (req, res) => {
  const u = await User.findById(req.user.id);
  res.json({
    name: u.name,
    email: u.email,
    creditScore: u.creditScore,
    nftBadge: `NFT-${u.creditScore}`,
    groupId: u.groupId,
  });
});


// Group routes
app.post('/api/group/create', authMiddleware, async (req, res) => {
  const group = await new Group({
    name: req.body.name,
    members: [req.user.id],
  }).save();
  await User.findByIdAndUpdate(req.user.id, { groupId: group._id });
  res.json({ message: 'Group created', group });
});


app.post('/api/group/join/:groupId', authMiddleware, async (req, res) => {
  const group = await Group.findById(req.params.groupId);
  if (!group) return res.status(404).json({ message: 'Group not found' });


  if (!group.members.includes(req.user.id)) {
    group.members.push(req.user.id);
    await group.save();
    await User.findByIdAndUpdate(req.user.id, { groupId: req.params.groupId });
  }
  res.json({ message: 'Joined group' });
});


app.post('/api/group/contribute', authMiddleware, async (req, res) => {
  const { amount } = req.body;
  const u = await User.findById(req.user.id);
  if (!u.groupId) return res.status(400).json({ message: 'Not in a group' });


  await Group.findByIdAndUpdate(u.groupId, { $inc: { insurancePool: amount } });
  res.json({ message: `Contributed $${amount}` });
});


app.get('/api/group/info', authMiddleware, async (req, res) => {
  const u = await User.findById(req.user.id);
  if (!u.groupId) return res.status(404).json({ message: 'Not in a group' });


  const g = await Group.findById(u.groupId);
  res.json({
    trustScore: g.trustScore,
    insurancePool: g.insurancePool,
    members: g.members,
  });
});


// Portfolio routes
app.post('/api/portfolio/connect', authMiddleware, async (req, res) => {
  const { stocks } = req.body;
  await Portfolio.findOneAndUpdate(
    { userId: req.user.id },
    { stocks },
    { upsert: true }
  );
  res.json({ message: 'Portfolio updated' });
});


app.get('/api/portfolio', authMiddleware, async (req, res) => {
  const pf = await Portfolio.findOne({ userId: req.user.id });
  res.json(pf || { stocks: [] });
});


// Loan utility
function calcBorrowable(portfolio) {
  const total = portfolio.stocks.reduce((s, stk) => s + stk.quantity * stk.marketPrice, 0);
  return total * 0.5;
}
app.get('/api/loans', authMiddleware, async (req, res) => {
  const loans = await Loan.find({ userId: req.user.id }).sort({ _id: -1 });
  res.json(loans);
});
// Loan routes
app.get('/api/loan/power', authMiddleware, async (req, res) => {
  const pf = await Portfolio.findOne({ userId: req.user.id });
  if (!pf) return res.status(400).json({ message: 'No portfolio' });
  res.json({ borrowable: calcBorrowable(pf) });
});


app.post('/api/loan/borrow', authMiddleware, async (req, res) => {
  const { amount } = req.body;
  const pf = await Portfolio.findOne({ userId: req.user.id });
  const limit = calcBorrowable(pf || { stocks: [] });
  if (amount > limit) return res.status(400).json({ message: 'Exceeds borrowable' });


  const loan = await new Loan({ userId: req.user.id, amount, approved: true }).save();
  res.json({ message: 'Loan approved', loan });
});


// Liquidation risk endpoint
app.get('/api/loan/liquidation-check', authMiddleware, async (req, res) => {
  // simplistic simulation: 30% chance of risk
  const atRisk = Math.random() > 0.7;
  res.json({ atRisk, message: atRisk ? 'Low collateral ratio!' : 'Safe' });
});


// Auto-roll loans
app.post('/api/loan/auto-roll', authMiddleware, async (req, res) => {
  const { amount } = req.body;
  const pf = await Portfolio.findOne({ userId: req.user.id });
  if (!pf) return res.status(400).json({ message: 'No portfolio' });


  const limit = calcBorrowable(pf);
  if (amount > limit)
    return res.status(400).json({ message: 'Risk too high, paused' });


  const loan = await new Loan({ userId: req.user.id, amount, approved: true }).save();
  res.json({ message: 'Micro‑loan issued', loan });
});


// FX simulation
app.post('/api/loan/fx-simulate', authMiddleware, (req, res) => {
  const { amount, currency } = req.body;
  const rates = { USD: 1, EUR: 0.85, INR: 83 };
const fxRate = rates[currency] || 1;
  const hedged = amount * fxRate * 0.98;
  res.json({ hedgedAmount: hedged, currency });
});


// AI rebalance suggestion
app.get('/api/ai/rebalance', authMiddleware, (_req, res) => {
  res.json({ suggestion: 'Reduce tech stocks by 10%, add 5% healthcare' });
});


// Loan submit & repay with trust score impact
app.post('/api/loan/submit', authMiddleware, async (req, res) => {
  const { amount, reason } = req.body;
  const loan = await new Loan({ userId: req.user.id, amount, approved: true, reason }).save();
  res.json({ message: 'Loan requested', loan });
});


app.post('/api/loan/repay', authMiddleware, async (req, res) => {
  const { loanId, amount } = req.body;
  const loan = await Loan.findById(loanId);
  if (!loan || loan.repaid) return res.status(400).json({ message: 'Invalid loan' });
  if (amount >= loan.amount) {
    loan.repaid = true;
    await loan.save();


    // Increase group's trustScore
    const u = await User.findById(loan.userId);
    if (u.groupId) await Group.findByIdAndUpdate(u.groupId, { $inc: { trustScore: 2 } });
    res.json({ message: `Repaid $${amount} — Trust score updated` });
  } else {
    res.json({ message: `Partial repayment of $${amount}` });
  }
});


// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`StockSet API running on port ${PORT}`));







