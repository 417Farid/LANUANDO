/**
 * Template Name: ComingSoon - v4.6.0
 * Template URL: https://bootstrapmade.com/comingsoon-free-html-bootstrap-template/
 * Author: BootstrapMade.com
 * License: https://bootstrapmade.com/license/
 */

function actualizar_servicio(){
    let inputFile = document.getElementById("formFile");
    let inputUrl = document.getElementById("foto").value;
    if(inputFile.files.length===0){
        document.formulario.submit();
    }else{
        eliminarServicio(-1,inputUrl).then(()=>{
           subirArchivo("servicios"); 
        });
    }
}

function guardar_imagenes() {
    let validar = comprobarInputs();
    if (validar === true) {
        let count = 1;
        Array.from(document.getElementsByName("file")).forEach((input) => {
            if (count !== 1) {
                subirImagen(input, count);
            }
            count++;
        });
    } else {
        alert("Por favor, termine de añadir las imagenes.");
    }

}

function comprobarInputs() {
    let count = 1;
    let validar = true;
    Array.from(document.getElementsByName("file")).forEach((input) => {
        if (count !== 1) {
            if (input.files.length === 0) {
                validar = false;
            }
        }
        count++;
    });
    return validar;
}

Array.from(document.getElementsByClassName('delete_button')).forEach((button) => {
    button.addEventListener('click', (e) => {
        e.preventDefault();
        let num = e.target.getAttribute('button');
        let id_imagen = e.target.getAttribute('id_imagen');
        let contenedor = document.querySelector("#container-" + num);
        let url = document.getElementById("img-preview-"+num).src;
        eliminarImagen(id_imagen,url);
        padre = contenedor.parentNode;
        padre.removeChild(contenedor);
    });
});

function buscarButtons() {
    Array.from(document.getElementsByClassName('eliminar_button')).forEach((button) => {
        button.addEventListener('click', (e) => {
            e.preventDefault();
            let id = e.target.getAttribute('button');
            let contenedor = document.querySelector("#contenedor-" + id);
            row = contenedor.parentNode;
            row.removeChild(contenedor);
        });
    });
}

function buscarInputs() {
    Array.from(document.getElementsByName("file")).forEach((input) => {
        input.addEventListener('change', (e) => {
            e.preventDefault();
            let id = e.target.getAttribute('input');
            let reader = new FileReader();
            reader.readAsDataURL(e.target.files[0]);
            reader.onload = function () {
                document.getElementById("contenedor-img-" + id).hidden = false;
                let preview = document.getElementById('preview-' + id);
                preview.src = reader.result;
                preview.height = 200;
            };
        });
    });
}

function agregar_imagen() {
    let fragment = document.createDocumentFragment();
    let contenedor = document.querySelector("#contenedor");
    let clone = contenedor.cloneNode(true);
    const array = document.getElementsByName("contenedor");
    let numCont = array.length - 1;
    clone.id = "contenedor-" + numCont;
    clone.querySelector('#contenedor-img').id = "contenedor-img-" + numCont;
    clone.querySelector('#preview').id = "preview-" + numCont;
    clone.querySelector('#figcaption').id = "figcaption-" + numCont;
    clone.querySelector('#figcaption-' + numCont).firstElementChild.setAttribute("button", numCont);
    clone.querySelector('#file').setAttribute("input", numCont);
    clone.hidden = false;
    fragment.appendChild(clone);
    let row = document.getElementById("row");
    row.appendChild(fragment);
    buscarInputs();
    buscarButtons();
}

(function () {
    "use strict";

    /**
     * Easy selector helper function
     */
    const select = (el, all = false) => {
        el = el.trim()
        if (all) {
            return [...document.querySelectorAll(el)]
        } else {
            return document.querySelector(el)
    }
    }

    /**
     * Easy event listener function
     */
    const on = (type, el, listener, all = false) => {
        let selectEl = select(el, all)
        if (selectEl) {
            if (all) {
                selectEl.forEach(e => e.addEventListener(type, listener))
            } else {
                selectEl.addEventListener(type, listener)
            }
    }
    }

    /**
     * Easy on scroll event listener 
     */
    const onscroll = (el, listener) => {
        el.addEventListener('scroll', listener)
    }

    /**
     * Back to top button
     */
    let backtotop = select('.back-to-top')
    if (backtotop) {
        const toggleBacktotop = () => {
            if (window.scrollY > 100) {
                backtotop.classList.add('active')
            } else {
                backtotop.classList.remove('active')
            }
        }
        window.addEventListener('load', toggleBacktotop)
        onscroll(document, toggleBacktotop)
    }

})()

switch (document.title) {
    case "LANUAN":
        document.getElementById("inicio-menu").style = "color:unset;";
        break;
    case "SERVICIOS":
        document.getElementById("servicios-menu").style = "color:unset;";
        break;
    case "NUEVO SERVICIO":
        document.getElementById("servicios-menu").style = "color:unset;";
        break;
    case "MODIFICAR SERVICIO":
        document.getElementById("servicios-menu").style = "color:unset;";
        break;
    case "CONTACTO":
        document.getElementById("contacto-menu").style = "color:unset;";
        break;
    case "CARRUSEL":
        document.getElementById("carrusel-menu").style = "color:unset;";
        break;
}