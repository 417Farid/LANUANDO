
package com.ufps.lanuan.service;

import com.ufps.lanuan.entities.Imagen;
import java.sql.SQLException;
import java.util.List;

public interface ImagenService {
    
    public List<Imagen> listarImagenes();
    public void guardar (Imagen imagen) throws SQLException;
    public void eliminar (Imagen imagen);
    public Imagen encontrarImagen (Imagen imagen);
}
