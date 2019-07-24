const express = require('express');
const router = express.Router();

const pool = require('../database');
const {isLogin}=require('../lib/seguridad');
router.get('/add',isLogin,(req, res) => {
    res.render('links/add');
});
router.post('/add',isLogin,async (req, res) => {
    const { title, url, description } = req.body;
    const newLink = {
        title,
        url,
        description,
        user_id: req.user.id
    };
    console.log(newLink);
    await pool.query('INSERT INTO links set ?', [newLink]);
    req.flash('success','link guaradado correctamente');
    res.redirect('/links');
});
router.get('/',isLogin, async (req, res) => {
    const links = await pool.query('SELECT * FROM links WHERE user_id = ?',[req.user.id]);
    console.log(links);
    res.render('links/list', { links });
});
router.get('/delete/:id',isLogin, async (req, res) => {
    const { id } = req.params;
    await pool.query('DELETE FROM links WHERE ID = ?', [id]);
    req.flash('success','link eliminado Correctamente')
    res.redirect('/links');

});
router.get('/edit/:id',isLogin,async (req, res) => {
    const { id } = req.params;
    const links = await pool.query('SELECT * FROM links WHERE id = ?', [id]);
    console.log(links[0]);
    res.render('links/edit', { link: links[0] });


});
router.post('/edit/:id', async (req, res) => {
    const { id } = req.params;
    const { title, description, url } = req.body;
    const newLink = {
        title,
        description,
        url
    }
    
    await pool.query('UPDATE links set ? WHERE id = ?', [newLink, id]);
    req.flash('success','link Actualizado Correctamente')
    res.redirect('/links');
     
});

module.exports = router;