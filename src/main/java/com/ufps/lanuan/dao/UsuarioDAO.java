package com.ufps.lanuan.dao;

import com.ufps.lanuan.entities.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UsuarioDAO extends JpaRepository<Usuario,Long>{
    
    Usuario findByUsername(String username);
}
