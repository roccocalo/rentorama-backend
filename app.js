const express = require('express');
const mongoose = require('mongoose');
const User = require('./models/User');
const { body, validationResult } = require('express-validator');
const bycrypt = require('bcryptjs');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

mongoose.connect(process.env.MONGO_URL)

app.get('/test', (req, res) => {
    res.json('test done correctly');
});

passport.use(new LocalStrategy({ usernameField: 'email' },
    async (email, password, done) => {
        try {
            const user = await User.findOne({ email });
            if (!user) {
                return done(null, false, { message: 'Incorrect email.' });
            }
            bycrypt.compare(password, user.password, (err, isMatch) => {
                if (err) { return done(err); }
                if (!isMatch) { return done(null, false, { message: 'Incorrect password.' }); }
                return done(null, user);
            });
        } catch (err) {
            return done(err);
        }
    }
));

const opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = process.env.JWT_SECRET; // replace with your JWT secret

passport.use(new JwtStrategy(opts, (jwt_payload, done) => {
    User.findById(jwt_payload.id, (err, user) => {
        if (err) {
            return done(err, false);
        }
        if (user) {
            return done(null, user);
        } else {
            return done(null, false);
        }
    });
}));

app.post('/signup',
    body('name').notEmpty().withMessage('name must not be empty.'),
    body('password').notEmpty().withMessage('Password must not be empty.'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long.'),
    async (req, res, next) => {
        const { name, email, password } = req.body;
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ messageErr: 'Email already exists.' });
        }
        bycrypt.hash(password, 10, async (err, hashedPassword) => {
            if (err) { return next(err); }
            const newUser = new User({
                name,
                email,
                password: hashedPassword,
            });
            await newUser.save();
            const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.json({ token });
        });
    });

app.post('/login', (req, res, next) => {
    passport.authenticate('local', { session: false }, (err, user, info) => {
        if (err) { return next(err); }
        if (!user) {
            if (info.message === 'Incorrect email.') {
                return res.status(400).json({ messageErr: 'Email not found.' });
            }
            if (info.message === 'Incorrect password.') {
                return res.status(400).json({ messageErr: 'Incorrect password.' });
            }
        }
        req.logIn(user, { session: false }, (err) => {
            if (err) { return next(err); }
            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
            return res.json({ token, user });
        });
    })(req, res, next);
});

app.get('/profile', passport.authenticate('jwt', { session: false }), (req, res) => {
    res.json({ message: 'User info', user: { id: req.user._id, name: req.user.name, email: req.user.email } });
});

app.listen(3000);