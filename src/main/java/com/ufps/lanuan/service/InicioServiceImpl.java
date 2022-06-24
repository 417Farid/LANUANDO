package com.ufps.lanuan.service;

import com.ufps.lanuan.dao.InicioDAO;
import com.ufps.lanuan.entities.Inicio;
import java.sql.SQLException;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class InicioServiceImpl implements InicioService{

    @Autowired
    private InicioDAO inicioDao;
    
    @Override
    @Transactional
    public void guardar(Inicio inicio)throws SQLException{
        inicioDao.save(inicio);
    }

    @Override
    @Transactional(readOnly=true)
    public Inicio encontrarInicio(Long id) {
        return inicioDao.findById(id).orElse(null);
    }    
    
    @Override
    @Transactional(readOnly=true)
    public List<Inicio> listarInicios() {
        return (List<Inicio>) inicioDao.findAll();
    }
}
