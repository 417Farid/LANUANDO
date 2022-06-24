package com.ufps.lanuan.entities;

import com.ufps.lanuan.util.EncriptarPassword;
import java.io.Serializable;
import javax.persistence.*;
import lombok.Data;
import javax.validation.constraints.NotEmpty;

@Entity
@Data
@Table(name = "usuario")
public class Usuario implements Serializable{
    private static final long serialVersionUID = 1L;
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column
    private long id_usuario;
        
    @NotEmpty
    private final String username = "lanuanpatios@ufps.edu.co";
    
    @NotEmpty
    @Column
    private final String password = encriptar("Lanuan2022Patios$");
    
    public String encriptar(String password){
        EncriptarPassword ep = new EncriptarPassword();
        return ep.encriptarPassword(password);
    }
    
}
