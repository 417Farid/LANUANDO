package com.ufps.lanuan.service;

import com.ufps.lanuan.dao.ServicioDAO;
import com.ufps.lanuan.entities.Servicio;
import java.sql.SQLException;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ServicioServiceImpl implements ServicioService{

    @Autowired
    private ServicioDAO servicioDao;
    
    @Override
    @Transactional(readOnly=true)
    public List<Servicio> listarServicios() {
        return (List<Servicio>) servicioDao.findAll();
    }

    @Override
    @Transactional
    public void guardar(Servicio servicio)throws SQLException{
        servicioDao.save(servicio);
    }

    @Override
    @Transactional
    public void eliminar(Servicio servicio){
        servicioDao.delete(servicio);
    }

    @Override
    @Transactional(readOnly=true)
    public Servicio encontrarServicio(Servicio servicio) {
        return servicioDao.findById(servicio.getId_servicio()).orElse(null);
    }    
}
