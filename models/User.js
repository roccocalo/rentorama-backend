const { unique } = require('jquery');
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    name: String,
    email: {type: String, unique: true},
    password: String
})

const UserModel = mongoose.model('User', UserSchema);

module.exports = UserModel;