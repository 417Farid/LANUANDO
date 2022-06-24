package com.ufps.lanuan.main;

import com.ufps.lanuan.entities.Inicio;
import com.ufps.lanuan.entities.Usuario;
import com.ufps.lanuan.service.ImagenService;
import com.ufps.lanuan.service.InicioService;
import com.ufps.lanuan.service.ServicioService;
import com.ufps.lanuan.service.UsuarioService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@Slf4j
public class ControladorInicio {

    @Autowired
    private ServicioService servicioService;

    @Autowired
    private ImagenService imagenService;
    
    @Autowired
    private InicioService inicioService;
    
    @Autowired
    private UsuarioService usuarioService;

    private void createUser() {
        var usuarios = usuarioService.listarUsuarios();

        if (usuarios.isEmpty()) {
            Usuario usuario = new Usuario();
            usuarioService.guardar(usuario);
        }
    }
    
    @GetMapping("/lanuan/")
    public String inicio(Model model) {
        try {
            createUser();
            var imagenes = imagenService.listarImagenes();
            model.addAttribute("imagenes", imagenes);
            var servicios = servicioService.listarServicios();
            model.addAttribute("servicios", servicios);
            Inicio inicio = inicioService.encontrarInicio(Long.parseLong("1"));
            if(inicio==null){
                inicio = new Inicio();
            }
            model.addAttribute("inicio", inicio);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        return "inicio";
    }
    
    @GetMapping("/lanuan/login")
    public String login(){
        return "login";
    }
    
    @GetMapping("/lanuan/logout")
    public String logout(){
        return "login";
    }
    
    @GetMapping("/lanuan/vista_360")
    public String vista360(){
        return "vista_360";
    }
}
