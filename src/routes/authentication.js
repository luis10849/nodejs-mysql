const express = require('express');
const router = express.Router();
const passport = require('passport');
const {isLogin,isNotLogin}=require('../lib/seguridad');


router.get('/registro',isNotLogin, (req, res) => {
    res.render('users/registro');
});
router.post('/registro',isNotLogin, passport.authenticate('local.registro', {
    successRedirect: '/perfil',
    failureRedirect: '/registro',
    failureFlash: true
}));
router.get('/login',isNotLogin, (req, res) => {
    res.render('users/login');
});
router.post('/login',isNotLogin, (req, res, next) => {
    passport.authenticate('local.login', {
        successRedirect: '/perfil',
        failureRedirect: '/login',
        failureFlash: true
    })(req, res, next);
});
router.get('/perfil',isLogin,(req, res) => {
    res.render('perfil');
});
router.get('/salir',isLogin, (req, res) => {
    req.logout();
    res.redirect('/login');
});
module.exports = router;