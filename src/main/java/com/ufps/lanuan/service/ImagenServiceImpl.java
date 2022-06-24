package com.ufps.lanuan.service;

import com.ufps.lanuan.dao.ImagenDAO;
import com.ufps.lanuan.entities.Imagen;
import java.sql.SQLException;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ImagenServiceImpl implements ImagenService{

    @Autowired
    private ImagenDAO imagenDao;
    
    @Override
    @Transactional(readOnly=true)
    public List<Imagen> listarImagenes() {
        return (List<Imagen>) imagenDao.findAll();
    }

    @Override
    @Transactional
    public void guardar(Imagen imagen)throws SQLException{
        imagenDao.save(imagen);
    }

    @Override
    @Transactional
    public void eliminar(Imagen imagen){
        imagenDao.delete(imagen);
    }

    @Override
    @Transactional(readOnly=true)
    public Imagen encontrarImagen(Imagen imagen) {
        return imagenDao.findById(imagen.getId_imagen()).orElse(null);
    }    
}
