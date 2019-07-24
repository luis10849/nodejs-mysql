module.exports={

      isLogin(req,res,next){
          if(req.isAuthenticated()){
               return next();
          }else{
              return res.redirect('/login');
          }
      },
      isNotLogin(req,res,next){
        if(!req.isAuthenticated()){
             return next();
        }else{
            return res.redirect('/perfil');
        }
    }

};
