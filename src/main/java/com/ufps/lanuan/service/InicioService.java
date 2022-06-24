
package com.ufps.lanuan.service;

import com.ufps.lanuan.entities.Inicio;
import java.sql.SQLException;
import java.util.List;

public interface InicioService {
    
    public void guardar (Inicio inicio) throws SQLException;
    public Inicio encontrarInicio (Long id);
    public List<Inicio> listarInicios();

}
