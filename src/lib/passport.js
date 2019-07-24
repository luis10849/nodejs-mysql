const passport = require('passport');
const Stratrgy = require('passport-local').Strategy;
const pool = require('../database');
const helpers = require('../lib/helpers');

passport.use('local.login', new Stratrgy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
}, async (req, username, password, done) => {
   
    
    const usuarios = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if(usuarios.length>0){
        const user= usuarios[0];
        const isValido=await helpers.comparar(password,user.password);
        if(isValido){
            done(null,user,req.flash('success','Bienvenido'+user.username));
        }else{
            done(null,false,req.flash('message','contraseña incorrecta'));
        }
    }else{
        return done(null,false,req.flash('message','el nombre de usuario no existe'));
    }
    
}));
passport.use('local.registro', new Stratrgy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
}, async (req, username, password, done) => {
    const { fullname } = req.body;
    const newUser = {
        username,
        password,
        fullname
    };
    newUser.password = await helpers.encryptar(password);
    const res = await pool.query('INSERT INTO users SET ?', [newUser]);
    newUser.id = res.insertId;
    return done(null, newUser);
}));
passport.serializeUser((user, done) => {
    done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
    const rows = await pool.query('SELECT * FROM users WHERE id = ?', [id]);
    done(null, rows[0]);
});