package com.ufps.lanuan.main;

import com.ufps.lanuan.entities.Imagen;
import com.ufps.lanuan.entities.Servicio;
import com.ufps.lanuan.entities.Inicio;
import com.ufps.lanuan.service.ImagenService;
import com.ufps.lanuan.service.InicioService;
import com.ufps.lanuan.service.ServicioService;
import java.util.Collection;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@Slf4j
public class ControladorIndex {

    @Autowired
    private ServicioService servicioService;

    @Autowired
    private ImagenService imagenService;

    @Autowired
    private InicioService inicioService;
    
    @GetMapping("/404.html")
    public String render404() {
        return "404";
    }

    @GetMapping("/lanuan/admin/")
    public String inicio(Model model, @AuthenticationPrincipal User user) {
        try {
            var inicios = inicioService.listarInicios();
            if (inicios.isEmpty()) {
                Inicio inicio = new Inicio();
                inicioService.guardar(inicio);
            }
            Inicio inicio = inicioService.encontrarInicio(Long.parseLong("1"));
            model.addAttribute("inicio", inicio);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        return userAuthentication(user);
    }

    private String userAuthentication(User user) {
        Collection<GrantedAuthority> roles = user.getAuthorities();

        for (GrantedAuthority role : roles) {
            if (role.getAuthority().equals("ROLE_ADMINISTRADOR")) {
                return "index";
            }
        }
        return "login";
    }

    @PostMapping("/lanuan/admin/Actualizar_Inicio")
    public String guardar_inicio(Inicio inicio, Model model) {
        try {
            Inicio aux = inicioService.encontrarInicio(Long.parseLong("1"));
            aux.setBienvenida(inicio.getBienvenida());
            aux.setMision(inicio.getMision());
            aux.setVision(inicio.getVision());
            inicioService.guardar(aux);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        model.addAttribute("inicio", inicio);
        return "redirect:/lanuan/admin/";
    }

    @GetMapping("/lanuan/admin/carrusel")
    public String carrusel(Model model) {
        var imagenes = imagenService.listarImagenes();
        model.addAttribute("imagenes", imagenes);
        return "carrusel";
    }

    @GetMapping("/lanuan/admin/servicios")
    public String servicios(Model model) {
        var servicios = servicioService.listarServicios();
        model.addAttribute("servicios", servicios);
        return "servicios";
    }

    @GetMapping("/lanuan/admin/contacto")
    public String contacto(Model model) {
        try {
            var inicios = inicioService.listarInicios();
            if (inicios.isEmpty()) {
                Inicio inicio = new Inicio();
                inicioService.guardar(inicio);
            }
            Inicio inicio = inicioService.encontrarInicio(Long.parseLong("1"));
            model.addAttribute("inicio", inicio);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        return "contacto";
    }

    @PostMapping("/lanuan/admin/contacto/Actualizar_Contacto")
    public String guardar_contacto(Inicio inicio, Model model) {
        try {
            Inicio aux = inicioService.encontrarInicio(Long.parseLong("1"));
            aux.setNumero(inicio.getNumero());
            aux.setCorreo(inicio.getCorreo());
            aux.setSemana(inicio.getSemana());
            aux.setFin_semana(inicio.getFin_semana());
            inicioService.guardar(aux);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        model.addAttribute("inicio", inicio);
        return "redirect:/lanuan/admin/contacto";
    }

    @PostMapping("/lanuan/admin/carrusel/guardar_imagenes")
    public String guardar_imagenes(@RequestParam(name = "cadena") String cadena) {
        try {
            String[] array = cadena.split(",");
            for (String x : array) {
                Imagen imagen = new Imagen();
                imagen.setFoto(x);
                imagenService.guardar(imagen);
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }

        return "redirect:/lanuan/admin/carrusel";
    }

    @GetMapping("/lanuan/admin/servicios/agregar_servicio")
    public String agregar_servicio(Servicio servicio) {
        return "nuevoServicio";
    }

    @GetMapping("/lanuan/admin/servicios/modificar_servicio/{id_servicio}")
    public String modificar_servicio(Model model, Servicio servicio) {
        try {
            servicio = servicioService.encontrarServicio(servicio);
            model.addAttribute("servicio", servicio);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        return "modServicio";
    }

    @PostMapping("/lanuan/admin/servicios/actualizar_servicio")
    public String actualizar_servicio(Model model, Servicio servicio) {
        try {
            servicioService.guardar(servicio);
            var servicios = servicioService.listarServicios();
            model.addAttribute("servicios", servicios);
        } catch (Exception e) {
            System.err.println(e.getMessage());
            return "modServicio";
        }

        return "redirect:/lanuan/admin/servicios";
    }

    @PostMapping("/lanuan/admin/servicios/guardar_servicio")
    public String guardar_servicio(Servicio servicio) {
        try {
            servicioService.guardar(servicio);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        return "redirect:/lanuan/admin/servicios";
    }

    @GetMapping("/lanuan/admin/servicios/eliminar_servicio/{id_servicio}")
    public String eliminarServicio(Servicio servicio, Model model) {
        try {
            servicioService.eliminar(servicio);
            var servicios = servicioService.listarServicios();
            model.addAttribute("servicios", servicios);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        return "redirect:/lanuan/admin/servicios";
    }

    @GetMapping("/lanuan/admin/carrusel/eliminar_imagen/{id_imagen}")
    public String eliminarImagen(Imagen imagen, Model model) {
        try {
            imagenService.eliminar(imagen);
            var imagenes = imagenService.listarImagenes();
            model.addAttribute("imagenes", imagenes);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        return "redirect:/lanuan/admin/carrusel";
    }
}
