package com.ufps.lanuan.entities;

import java.io.Serializable;
import javax.persistence.*;
import lombok.Data;
import javax.validation.constraints.NotEmpty;

@Entity
@Data
@Table(name = "imagen")
public class Imagen implements Serializable{
    private static final long serialVersionUID = 1L;
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column
    private long id_imagen;
    
    @NotEmpty
    @Column(length=255)
    private String foto;
    
}
