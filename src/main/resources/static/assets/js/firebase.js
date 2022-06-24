// Your web app's Firebase configuration
const firebaseConfig = {
    apiKey: "AIzaSyB7bITIgz7KHsiNChmVt7sT40EbOfsWVAI",
    authDomain: "lanuan-ufps.firebaseapp.com",
    projectId: "lanuan-ufps",
    storageBucket: "lanuan-ufps.appspot.com",
    messagingSenderId: "458738199141",
    appId: "1:458738199141:web:5fdd4c4256290dcae1748c"
};
// Initialize Firebase
firebase.initializeApp(firebaseConfig);

async function subirArchivo(carpeta) {
    inputFile = document.getElementById("formFile");
    if (inputFile.files.length === 0) {
        alert("Por favor seleciona un archivo");
        return;
    } else {
        let file = inputFile.files[0];
        let storageRef = firebase.storage().ref(carpeta);
        const fileName = file.name.toString();
        let thisRef = storageRef.child(fileName+"-"+getRandom());
        const task = thisRef.put(file);
        firebase.auth().signInAnonymously()
                .then(function () {
                    task
                            .then(snapshot => snapshot.ref.getDownloadURL())
                            .then(url => {
                                alert("Imagen cargada...");
                                document.getElementById("foto").value = url;
                                document.formulario.submit();
                            });

                }).catch(function (error) {
            var errorCode = error.code;
            var errorMessage = error.message;
            console.log(errorCode);
            console.log(errorMessage);
        });
    }
}

async function subirImagen(inputFile, index) {
    let file = inputFile.files[0];
    let storageRef = firebase.storage().ref("carrusel");
    const fileName = file.name.toString();
    let thisRef = storageRef.child(fileName+"-"+getRandom());
    const task = thisRef.put(file);
    firebase.auth().signInAnonymously()
            .then(function () {
                task
                        .then(snapshot => snapshot.ref.getDownloadURL())
                        .then(url => {
                            document.getElementById("imagenes").value+=url+",";
                            let num = document.getElementsByName("file").length;
                            if(index === num){
                                document.formulario.submit();
                            }
                        });

            }).catch(function (error) {
        var errorCode = error.code;
        var errorMessage = error.message;
        console.log(errorCode);
        console.log(errorMessage);
    });
}

async function eliminarServicio(id, url) {
    let foto = url;
    if (foto === null || foto === "" || foto === "undefined") {
        alert("Servicio eliminado.");
        document.location.href = "/lanuan/admin/servicios/eliminar_servicio/" + id;
    } else {
        let storageRef = firebase.storage().ref("servicios");
        let thisRef = storageRef.child(obtenerNombreImg(url));
        thisRef.delete().then(function () {
            if(id!==-1){
                alert("Servicio eliminado.");
                document.location.href = "/lanuan/admin/servicios/eliminar_servicio/" + id;
            }
        }).catch(function (error) {
            console.log(error);
        });
    }
}

async function eliminarImagen(id, url) {
    let foto = url;
    if (foto === null || foto === "" || foto === "undefined") {
        alert("Imagen eliminada.");
        document.location.href = "/lanuan/admin/carrusel/eliminar_imagen/" + id;
    } else {
        let storageRef = firebase.storage().ref("carrusel");
        let thisRef = storageRef.child(obtenerNombreImg(url));
        thisRef.delete().then(function () {
            alert("Imagen eliminada.");
            document.location.href = "/lanuan/admin/carrusel/eliminar_imagen/" + id;
        }).catch(function (error) {
            console.log(error);
            document.location.href = "/lanuan/admin/carrusel/eliminar_imagen/" + id;
        });
    }
}

function obtenerNombreImg(url) {
    let array = url.split("%2F");
    array = array[1].split("?");
    return array[0];
}

function getExtension(fileName) {
    const file = fileName;
    let extension = "";
    let char = "";
    for (let i = file.length; i > -1; i--) {
        char = file.toString().charAt(i);
        extension += char;
        if (char === ".")
            i = 0;
    }
    let cadena = "";
    for (let i = extension.length; i > -1; i--) {
        cadena += extension.charAt(i);
    }
    return cadena;
}

function getRandom() {
  return Math.floor(Math.random() * (10000 - 1) + 1);
}

function hashCode(s) {
    let h = 0;
    for (let i = 0; i < s.length; i++)
        h = Math.imul(31, h) + s.charCodeAt(i) | 0;

    return Math.abs(h);
}