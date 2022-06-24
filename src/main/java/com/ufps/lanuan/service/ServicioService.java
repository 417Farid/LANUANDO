
package com.ufps.lanuan.service;

import com.ufps.lanuan.entities.Servicio;
import java.sql.SQLException;
import java.util.List;

public interface ServicioService {
    
    public List<Servicio> listarServicios();
    public void guardar (Servicio servicio) throws SQLException;
    public void eliminar (Servicio servicio);
    public Servicio encontrarServicio (Servicio servicio);
}
