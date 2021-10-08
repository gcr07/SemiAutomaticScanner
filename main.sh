#!/bin/bash

sweepPing () {

   echo "Dentro de sweePing"
   nmap -sP -n $1 > ips.tmp
   cat ips.tmp | grep "for" | grep -oP "\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}" > ipsolas.tmp

   
}

osRecon()
{

echo "Dentro de osRecon"
cat ipsolas.tmp | while read line; do

  	echo -e "$(./osrecon.py $line):$line">> os.tmp
  	
done

}


arpIP ()
{


cat ipsolas.tmp | while read line; do

nmap -n -sP $line > super1tmp.tmp

bandera=$(cat super1tmp.tmp	| grep -io "Host seems down")

if [[ $bandera != "Host seems down" ]]; then

ip=$(cat super1tmp.tmp | grep -oP "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" )

#echo "Aqui esta el error sis IP ${ip}"
mac=$(cat super1tmp.tmp | grep -oiE '([0-9A-F]{2}:){5}[0-9A-F]{2}' )
#echo "Aqui esta el error si MAC ${mac}"
vendor=$(cat super1tmp.tmp | grep "MAC" | grep -Po '(?<=\().*(?=\))')

#echo "Aqui esta el error sVendor ${vendor}"

echo "${ip}_${mac}_${vendor}" >> ipmacvendor.tmp

fi	
done

rm -f super1tmp.tmp

}



function extractPorts()
{
ip_address=$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u)
open_ports=$(cat $1 | grep -oP '\d{1,5}/open' |awk '{print $1}' FS="/" | xargs| tr ' ' ',')
open_ports2=$(cat $1 | grep -oP '\d{1,5}/open' |awk '{print $1}' FS="/" | xargs)
echo "${ip_address}:${open_ports}" >> extractedports.tmp
echo "${ip_address}:${open_ports2}" >> buscandopuerto80.tmp
}



buscaPuertosAbiertos()
{
	echo "adentro buscarpuertos"

cat ipsolas.tmp | while read line; do
	
	
if [[ $puertos == "puertost" ]]; then

	if [ "$(id -u)" == "0" ]; then
	
  	nmap -n -Pn -p- -sS --min-rate 5000 --open -vvv $line -oG allPorts.tmp
  	echo "despues de en teoria acabar el escaneo"
  	extractPorts allPorts.tmp 
  	echo "despues de meter todo en extracted ports -P- PUERTOS1"

else
  	nmap -n -Pn -p- --open -vvv -T5 $line -oG allPorts1.tmp
  	echo "despues de en teoria acabar el escaneo"
  	extractPorts allPorts1.tmp
  	echo "despues de meter todo en extracted ports -P- PUERTOS2"

fi

else

	if [ "$(id -u)" == "0" ]; then
	
  	nmap -n -Pn -sS --open -vvv $line -oG allPorts.tmp
  	echo "despues de en teoria acabar el escaneo"
  	extractPorts allPorts.tmp
  	
  	echo "despues de meter todo en extracted ports -P- PUERTOS3"

else
  	nmap -n -Pn --open -vvv $line -oG allPorts1.tmp
  	echo "despues de en teoria acabar el escaneo"
  	extractPorts allPorts1.tmp
  	echo "despues de meter todo en extracted ports -P- PUERTOS4"

fi

fi	
done
}


deteccionServicios(){

echo "adentro de deteccio de servicios"
rm -Rf servicios/*.html
mkdir servicios

cat extractedports.tmp | while read line; do
  	ipaddr=''
  	ports=''
  	#echo " antes de ipaddr--------"
 	ipaddr=$(echo "$line" | awk '{print $1}' FS=:)
 	#echo $ipaddr
 	ports=$(echo "$line" | awk '{print $2}' FS=:)
 	#echo $ports

 	if [[ -z "$ports" ]]; then
 		 echo "String is empty"
	elif [[ -n "$ports" ]]; then
  		nmap -n -Pn -sC -sV -p $ports  -oN targeted.tmp $ipaddr -oX $ipaddr.xml 
  		echo $ipaddr >> servicios/listadeipserviciohtml.tmp
	fi

 	echo "un escaneo terminado -----------"
done

cat servicios/listadeipserviciohtml.tmp | while read line2; do

xsltproc $line2.xml > servicios/$line2.html 
  
done

rm -f *.xml

}



scanVuln(){

	echo "adentro de scanvuln"

cat extractedports.tmp | while read line; do
	
  
  	ipaddr=''
  	ports=''
  	#echo " antes de ipaddr--------"
 	ipaddr=$(echo "$line" | awk '{print $1}' FS=:)
 	#echo $ipaddr
 	ports=$(echo "$line" | awk '{print $2}' FS=:)
 	#echo $ports

 	if [[ -z "$ports" ]]; then
 		 echo "String is empty"
	elif [[ -n "$ports" ]]; then
		#echo "apunto de ejcutar nmap con $ipaddr"
		#echo "apunto de ejecutar nmap con $ports"
  		nmap -n -Pn -vvv -T5 --script "vuln and safe" -p $ports  -oN vuln.tmp $ipaddr -oX $ipaddr.xml
  		echo $ipaddr >> vulnerabilidades/vulnlista.tmp
	fi
done


cat vulnerabilidades/vulnlista.tmp | while read line2; do

xsltproc $line2.xml > vulnerabilidades/$line2.html 
  
done

rm -f *.xml



}


whatweb1(){

echo " Dentro de whatweb"
cat buscandopuerto80.tmp | while read line; do
		
  ar=''
  echo "$line" | awk '{print $2}' FS=:| tr ' ' '\n' > supertmp.tmp

	cat supertmp.tmp | while read line2; do

  		
  		if [[ -z "$line2" ]]; then
 			 echo "String is empty"
		elif [[ -n "$line" ]]; then
 			 
 	 if [[ $line2 -eq 80 ]]; then
 			 	echo "se encontro un 80 en $(echo "$line" | awk '{print $1}' FS=:)"
 			 	whatweb --log-brief=reconocimientoweb/$(echo "$line" | awk '{print $1}' FS=:).tmp http://$(echo "$line" | awk '{print $1}' FS=:)
 			 	echo $(echo "$line" | awk '{print $1}' FS=:) >> reconocimientoweb/listareconweb.tmp
 			 else
 			 	echo 
 			 fi				 
		fi
 	done
done
 	rm -f supertmp.tmp


}


fuzzgo(){


echo " Dentro de gobuster"
cat buscandopuerto80.tmp | while read line; do
	
  ar=''
  echo "$line" | awk '{print $2}' FS=:| tr ' ' '\n' > supertmp.tmp

	cat supertmp.tmp | while read line2; do

  		
  		if [[ -z "$line2" ]]; then
 			 echo "String is empty"
		elif [[ -n "$line" ]]; then
 			 
 			 if [[ $line2 -eq 80 ]]; then
 			 	echo " Fuzz se encontro un 80 en $(echo "$line" | awk '{print $1}' FS=:)"
 			 	echo "DENTRO CUANTAS VECES PASO POR AQUI"
 			 	go/gobuster dir -e -u http://$(echo "$line" | awk '{print $1}' FS=:)/ -w go/wordlist.txt > fuzzeo/$(echo "$line" | awk '{print $1}' FS=:).tmp
 			 	echo $(echo "$line" | awk '{print $1}' FS=:) >> fuzzeo/listafuzzeo.tmp

 			 else
 			 	echo 
 			 fi				 
		fi
 	done
done

}





crearTablaIp(){

echo "CrearTablaIp"
#echo "<h1> Computadoras Conectadas a Esta Red </h1>" >> tablaipyso.tmp
echo "<div class=\"container-fluid mt-3\" style=\"background:#6B1740\">" >> tablaipyso.tmp
echo "<div class=\"row\">" >> tablaipyso.tmp
echo "<div class=\"col\">" >> tablaipyso.tmp
echo "<h1 class=\"text-center text-white\"><small><strong>Computadoras Conectadas A Esta Red</strong></small></h1>" >> tablaipyso.tmp
echo "</div>" >> tablaipyso.tmp
echo "</div>" >> tablaipyso.tmp
echo "</div>" >> tablaipyso.tmp
echo "<br>" >> tablaipyso.tmp
echo "<br>" >> tablaipyso.tmp
echo "<div>" >> tablaipyso.tmp
echo "<table class=\"table table-hover\">" >> tablaipyso.tmp
echo "<thead>" >> tablaipyso.tmp
echo "<tr>" >> tablaipyso.tmp
echo "<th scope=\"col\">Direccion IP</th>" >> tablaipyso.tmp
echo "<th scope=\"col\">Sistema Operativo</th>" >> tablaipyso.tmp
echo "</tr>" >> tablaipyso.tmp
echo "</thead>" >> tablaipyso.tmp
echo "<tbody>" >> tablaipyso.tmp

cat os.tmp | while read line; do
	
ip1=$(echo $line | awk '{print $2}' FS=:)
osr=$(echo $line | awk '{print $1}' FS=:)
echo "<tr>" >> tablaipyso.tmp

echo "<th scope=\"row\">${ip1}</th>" >> tablaipyso.tmp
echo "<td>${osr}</td>" >> tablaipyso.tmp
echo "</tr>" >> tablaipyso.tmp

done

echo "</tbody>" >> tablaipyso.tmp
echo "</table> " >> tablaipyso.tmp
echo "</div>" >> tablaipyso.tmp

}



crearTablaMAC(){

echo "CrearTablaMac"
#echo "<h1> Reconocimiento de Dispositivos </h1>" >> tablamac.tmp
echo "<div class=\"container-fluid mt-3\" style=\"background:#6B1740\">" >> tablamac.tmp
echo "<div class=\"row\" >" >> tablamac.tmp
echo "<div class=\"col\">" >> tablamac.tmp
echo "<h1 class=\"text-center text-white\"><small><strong>Reconocimiento De Dispositivos</strong></small></h1>" >> tablamac.tmp
echo " </div>" >> tablamac.tmp
echo "</div>" >> tablamac.tmp
echo "</div>" >> tablamac.tmp
echo "<br>" >> tablamac.tmp
echo "<br>" >> tablamac.tmp
echo "<div>"  >> tablamac.tmp

echo "<table class="table table-hover">" >> tablamac.tmp
echo "<thead>" >> tablamac.tmp
echo "<tr>" >> tablamac.tmp
echo "<th scope=\"col\">Direccion IP</th>" >> tablamac.tmp
echo "<th scope=\"col\">Direccion MAC</th>" >> tablamac.tmp
echo "<th scope=\"col\">Dispositivo Encontrado</th>" >> tablamac.tmp
echo "</tr>" >> tablamac.tmp
echo "</thead>" >> tablamac.tmp
echo  "<tbody>" >> tablamac.tmp

cat ipmacvendor.tmp | while read line; do
	
ip1=$(echo $line | awk '{print $1}' FS=_)
mac=$(echo $line | awk '{print $2}' FS=_)
ven=$(echo $line | awk '{print $3}' FS=_)

if [[ -z "$ip1" ]]; then
  ip=$(echo "No Detectado!")
elif [[ -z "$mac" ]]; then
  mac=$(echo "No Detectado!")
  ven=$(echo "-") 
fi


echo "<tr>" >> tablamac.tmp

echo "<th scope=\"row\">${ip1}</th>" >> tablamac.tmp
echo "<td>${mac}</td>" >> tablamac.tmp
echo "<td>${ven}</td>" >> tablamac.tmp
echo "</tr>" >> tablamac.tmp

done
echo "</tbody>" >> tablamac.tmp
echo "</table> " >> tablamac.tmp
echo "</div> " >> tablamac.tmp
echo "</br> " >> tablamac.tmp

}



crearTablaPuertos(){

echo "crearTablaPuertos"

#echo "</br> " >> tablapuertos.tmp
#echo "<h1> Deteccion de servicios Corriendo en Puertos Abiertos </h1>" >> tablapuertos.tmp
echo "<div class=\"container-fluid mt-3\" style=\"background:#6B1740\">" >> tablapuertos.tmp
echo "<div class=\"row\">" >> tablapuertos.tmp
echo "<div class=\"col\">" >> tablapuertos.tmp
echo "<h1 class=\"text-center text-white\"><small><strong>Deteccion De Servicios Corriendo En Puertos Abiertos</strong></small></h1>" >> tablapuertos.tmp
echo "</div>" >> tablapuertos.tmp
echo "</div>" >> tablapuertos.tmp
echo "</div>" >> tablapuertos.tmp
echo "<br>" >> tablapuertos.tmp
echo "<br>" >> tablapuertos.tmp
echo "<div>" >> tablapuertos.tmp


echo "<table class=\"table table-hover\">" >> tablapuertos.tmp
echo "<thead>" >> tablapuertos.tmp
echo "<tr>" >> tablapuertos.tmp
echo "<th scope=\"col\">Direccion IP</th>" >> tablapuertos.tmp
echo " <th scope=\"col\">Puertos Abiertos</th>" >> tablapuertos.tmp
echo "</tr>" >> tablapuertos.tmp

  echo "</thead>" >> tablapuertos.tmp
  echo "<tbody>" >> tablapuertos.tmp

cat extractedports.tmp  | while read line; do
	
ip1=$(echo $line | awk '{print $1}' FS=:)
ports=$(echo $line | awk '{print $2}' FS=:)



if [[ -z "$ports" ]]; then
ports=$(echo "Todos Los Puertos Estan Cerrados!")
echo "<tr>" >> tablapuertos.tmp

echo "<th scope=\"row\">${ip1}</th>" >> tablapuertos.tmp
echo "<td>${ports}</td>" >> tablapuertos.tmp
echo "</tr>" >> tablapuertos.tmp

else

echo "<tr>" >> tablapuertos.tmp
echo "<th scope=\"row\"><a href=\"servicios/${ip1}.html\">${ip1}</a></td>" >> tablapuertos.tmp
echo "<td>${ports}</td>" >> tablapuertos.tmp
echo "</tr>" >> tablapuertos.tmp
fi

done
  
  echo "</tbody>" >> tablapuertos.tmp
echo "</table> " >> tablapuertos.tmp
echo "</div> " >> tablapuertos.tmp

}


crearTablaVuln(){

echo "CrearTablaVuln"


echo "<div class=\"container-fluid mt-3\" style=\"background:#6B1740\">" >> tablavuln.tmp
echo "<div class=\"row\">" >> tablavuln.tmp
echo "<div class=\"col\">" >> tablavuln.tmp
echo "<h1 class=\"text-center text-white\"><small><strong> Analisis De Vulnerabilidades </strong></small></h1>" >> tablavuln.tmp
echo "</div>" >> tablavuln.tmp
echo "</div>" >> tablavuln.tmp
echo "</div>" >> tablavuln.tmp
echo "<br>" >> tablavuln.tmp
echo "<br>" >> tablavuln.tmp
echo "<div>" >> tablavuln.tmp



#echo "</br> " >> tablavuln.tmp
#echo "<h1> Deteccion de Vulnerabilidades  </h1>" >> tablavuln.tmp
#echo "<table> " >> tablavuln.tmp
#echo "<tr>" >> tablavuln.tmp
echo "<table class=\"table table-hover\">" >> tablavuln.tmp
echo "<thead>" >> tablavuln.tmp
echo "<tr>" >> tablavuln.tmp
echo "<th scope=\"col\">Direccion IP </th>" >> tablavuln.tmp
echo "<th scope=\"col\">Acciones Realizadas </th>" >> tablavuln.tmp
echo "</tr>" >> tablavuln.tmp
echo "</thead>" >> tablavuln.tmp
echo "<tbody>" >> tablavuln.tmp

cat vulnerabilidades/vulnlista.tmp  | while read line; do
	

echo "<tr>" >> tablavuln.tmp
echo "<th scope=\"row\"><a href=\"vulnerabilidades/${line}.html\">${line}</a></td>" >> tablavuln.tmp
echo "<td> Escaneo De Vulnerabilidades En Puertos Abiertos! </td>" >> tablavuln.tmp

echo "</tr>" >> tablavuln.tmp


done
echo "</tbody>" >> tablavuln.tmp
echo "</table> " >> tablavuln.tmp
echo "</div> " >> tablavuln.tmp
}


crearTablaWhat(){


echo "AAAAAAAAAAAAAAAAAAAAAA CrearTablaWhat AAAAAAAAAAAAAAAAAAA"

#echo "</br> " >> tablawhat.tmp
#echo "<h1> Reconocimiento de Servidores si Esta abierto el puerto 80  </h1>" >> tablawhat.tmp

echo "<div class=\"container-fluid mt-3\" style=\"background:#6B1740\">" >> tablawhat.tmp
echo "<div class=\"row\">" >> tablawhat.tmp
echo "<div class=\"col\">" >> tablawhat.tmp
echo "<h1 class=\"text-center text-white\"><small><strong>Reconocimiento Servidores Web HTTP</strong></small></h1>" >> tablawhat.tmp
echo "</div>" >> tablawhat.tmp
echo "</div>" >> tablawhat.tmp
echo "</div>" >> tablawhat.tmp
echo "<br>" >> tablawhat.tmp
echo "<br>" >> tablawhat.tmp
echo "<div>" >> tablawhat.tmp

echo "<table class=\"table table-hover\">" >> tablawhat.tmp
echo "<thead>" >> tablawhat.tmp
echo "<tr>" >> tablawhat.tmp
echo "<th scope=\"col\">Direccion IP </th>" >> tablawhat.tmp
echo "<th scope=\"col\">Acciones Realizadas </th>" >> tablawhat.tmp
#echo "<th>  Puertos Abiertos </th>" >> tablawhat.tmp
echo "</tr>" >> tablawhat.tmp
echo "</thead>" >> tablawhat.tmp
echo "<tbody>" >> tablawhat.tmp

cat reconocimientoweb/listareconweb.tmp  | while read line; do
	

echo "<tr>" >> tablawhat.tmp
echo "<th scope=\"col\"><a href=\"reconocimientoweb/${line}.html\">${line}</a></td>" >> tablawhat.tmp
echo "<td> Reconocimiento HTTP en puerto 80! (Abierto) </td>" >> tablawhat.tmp
echo "</tr>" >> tablawhat.tmp


done
echo "</tbody>" >> tablawhat.tmp
echo "</table> " >> tablawhat.tmp
echo "</div> " >> tablawhat.tmp


echo "------------Termina crearTablaWhat--------------"

}



Crearwhat(){

echo "Crearwhat--------------"

 	cat reconocimientoweb/listareconweb.tmp | while read line3; do

		echo "${line3}.tmp"
		file=$(echo "${line3}.html")
		echo "FILE: ${file}"
		echo "LINE 3"
		buff=$(cat "reconocimientoweb/${line3}.tmp" | tr ',' '\r\n')
		echo "ABAJO DE buff="
		#echo "OYE"
		#echo "BUFF ${buff}"


cat << EOF > reconocimientoweb/$file 

<!doctype html>
<html lang="en">
  <head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" integrity="sha384-JcKb8q3iqJ61gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP+VmmDGMN5t9UJ0Z" crossorigin="anonymous">
    <link rel="stylesheet" type="text/css" href="css/styleR.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <!-- Custom styles for this template -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css">
    <link rel="icon" type="image/svg" href="img/ipn.png" />
    <title>Fuzzing</title>
    <link rel="stylesheet" type="text/css" href="noti.css">
  </head>
  <body>


<div class="container-fluid mt-3" style="background:#6B1740">
<div class="row">
<div class="col">
<h1 class="text-center text-white"><small><strong>Resultados</strong></small></h1>
   </div>
  </div>
</div>
<br>
 <br>
 <br>
<div> 
<h2><small><strong> Tecnologias Encontradas </strong></small> </h2>
</div>


<table class="table table-hover">
  <thead>
	<tr> 
		<th scope="col">Direccion </th>
		<th scope="col">Teconologias </th>

	</tr>

	<tr>
		<th scope="col">http://$line3:80</strong> </th>	

		<td> $buff </td>	
	</tr>
	</tr>
  </tbody>
</table>
<br>
 <br>
 <br>

<p class="francesa"><strong>Nota: </strong> Este escaneo reconoce tecnologías web, incluyendo los sistemas de gestión de contenidos (CMS), plataformas de blogs, verciones de JQuery, bibliotecas de JavaScript, servidores web y vercion de PHP. </p>

 <br>
 <br>
 <br>


<!--FOOTER -->

<footer class=" bg-dark page-footer pt-2 " >

   <!-- Footer Links -->
   <div class="container-fluid">
   
   <!-- Copyright -->

   <div class="col-md-6 mx-auto text-center text-white mt-5">IPN ESIME Zacatenco Junio 2021 &copy; 

   </div>
  </div>  
  
   <!-- Copyright -->


 </footer>

 <!-- Footer -->

   <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
   </body>
</html>


EOF
 	done

}





CrearFuzz(){


echo "ccccccccccccccccccccc DENTRO CrearFuzz ccccccccccccccccccccccc"
 	cat fuzzeo/listafuzzeo.tmp | while read line3; do
 	#cat listafuzzeo.tmp | while read line3; do	
 		echo "Archivo"
		echo "${line3}.tmp"
		file=$(echo "${line3}.tmp")
		fileh=$(echo "${line3}.html")
		#echo "LINE 3"
		#buff=$(cat "${line3}.tmp" | tr ',' '\r\n')
		url=$(cat fuzzeo/$file | grep "Url:" | awk '{print $3}')
		lista=$(cat fuzzeo/$file | grep "Wordlist:" | awk '{print $3}')
		codes=$( cat fuzzeo/$file | grep "Status codes:" | awk '{print $4}')
		res=$(cat fuzzeo/$file | grep "(Status:" )


		echo "LAS OPCIONES DE FUZZ"
		echo "FILE: ${file}"
		echo "URL: ${url}"
		echo "Lista: ${lista}"
		echo "codes: ${codes}"
		echo "res: ${res}"

cat << EOF > fuzzeo/$fileh 

<!doctype html>
<html lang="en">
  <head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" integrity="sha384-JcKb8q3iqJ61gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP+VmmDGMN5t9UJ0Z" crossorigin="anonymous">
    <link rel="stylesheet" type="text/css" href="css/styleR.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <!-- Custom styles for this template -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css">
    <link rel="icon" type="image/svg" href="img/ipn.png" />
    <title>Fuzzing</title>
    <link rel="stylesheet" type="text/css" href="noti.css">
  </head>
  <body>



<div class="container-fluid mt-3" style="background:#6B1740">
<div class="row">
<div class="col">
<h1 class="text-center text-white"><small><strong>Resultados</strong></small></h1>
   </div>
  </div>
</div>

<div> 
<h2><small><strong> Datos</strong></small> </h2>

<p><strong> URL: </strong> $url </p>
<p><strong> Diccionario: </strong> $lista </p> 
<p><strong> Codigos De Estado Http Probados: </strong> $codes </p>
</div>
<div > 
<table class="table table-hover">
  <thead>
    <tr>
		<th scope="col">Recursos Encontrados (URI) </th>
	</tr>

	<tr>
		<td><pre>$res</pre> </td>	
	</tr>
		<tr>
		<td> </td>	
	</tr>
  </tbody>
</table>
</div>
<p class="francesa"><strong>Nota: </strong>Este escaneo es utilizado para realizar fuerza bruta a: URIs 
 (directorios y archivos) en sitios web puede encontrar rutas y archivos ocultos  si es que existe un servidor en la red.</p>


<!--FOOTER -->

<footer class=" bg-dark page-footer pt-2 " >

   <!-- Footer Links -->
   <div class="container-fluid">
   
   <!-- Copyright -->

   <div class="col-md-6 mx-auto text-center text-white mt-5">IPN ESIME Zacatenco Junio 2021 &copy; 

   </div>
  </div>  
  
   <!-- Copyright -->
 
 </footer>

 <!-- Footer -->

   <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
   </body>
</html>

EOF
 	done

}





crearTablaFuzz(){

	echo " crearTablaFuzz"

#echo "</br> " >> tablafuzz.tmp
#echo "<h1>  Fuerza Bruta De Directorios </h1>" >> tablafuzz.tmp

echo "<div class=\"container-fluid mt-3\" style=\"background:#6B1740\">" >> tablafuzz.tmp
echo "<div class=\"row\">" >> tablafuzz.tmp
echo "<div class=\"col\">" >> tablafuzz.tmp
echo "<h1 class=\"text-center text-white\"><small><strong>Fuerza Bruta En Directorios Y Archivos En Un Servidor</strong></small></h1>" >> tablafuzz.tmp
echo "</div>" >> tablafuzz.tmp
echo "</div>" >> tablafuzz.tmp
echo "</div>" >> tablafuzz.tmp
echo "<br>" >> tablafuzz.tmp
echo "<br>" >> tablafuzz.tmp
echo "<div>" >> tablafuzz.tmp

echo "<table class=\"table table-hover\">" >> tablafuzz.tmp
echo "<thead>" >> tablafuzz.tmp
echo "<tr>" >> tablafuzz.tmp
echo "<th scope=\"col\">Direccion IP </th>" >> tablafuzz.tmp
echo "<th scope=\"col\">Acciones Realizadas </th>" >> tablafuzz.tmp
echo "</tr>" >> tablafuzz.tmp
echo "</thead>" >> tablafuzz.tmp
echo "<tbody>" >> tablafuzz.tmp

cat fuzzeo/listafuzzeo.tmp  | while read line; do
 

echo "<tr>" >> tablafuzz.tmp
echo "<th scope=\"col\"><a href=\"fuzzeo/${line}.html\">${line}</a></td>" >> tablafuzz.tmp
echo "<td> Se Intenta Encontrar Rutas O Archivos Ocultos</td>" >> tablafuzz.tmp
echo "</tr>" >> tablafuzz.tmp

done

echo "</tbody>" >> tablafuzz.tmp
echo "</table> " >> tablafuzz.tmp
echo "</div> " >> tablafuzz.tmp
}


CrearNotificacion()
{
	echo "dentro de crear notificacion"
	bueno=$(ls vulnerabilidades/*.html | xargs grep -o "VULNERABLE:")
	echo "$bueno"

		if [[ -z "$bueno" ]]; then
 		 echo "String is empty"
 		 echo " " > noti.tmp
	else
		echo "se cre la notificacion"
cat << EOF > noti.tmp
  <section>
        <!-- Error Alert -->
    <div class="alert alert-danger alert-dismissible fade show">
        <strong>VULNERABLE!</strong> Se detecto una vulnerabilidad en un host revisar tabla de Analisis de Vulnerabilidades.
        <button type="button" class="close" data-dismiss="alert">&times;</button>
    </div>
</section>
EOF
	fi

 	echo "un escaneo terminado -----------"

  

}


CrearTablaMadre(){


cat << EOF > res.html 


<!doctype html>
<html lang="en">
  <head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" integrity="sha384-JcKb8q3iqJ61gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP+VmmDGMN5t9UJ0Z" crossorigin="anonymous">
    <link rel="stylesheet" type="text/css" href="css/styleR.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <!-- Custom styles for this template -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css">
    <link rel="icon" type="image/svg" href="img/ipn.png" />
    <title>SADRLANC</title>
    <link rel="stylesheet" type="text/css" href="noti.css">
  </head>
  <body>
<!--HEADER -->
<!--PC-->
<!--YO Gerardo Puse esto -->


$tablanotificacion


<!--Aqui Acaba es una Notificacion -->

<div class="d-none d-sm-none d-md-block">
  <div class="row container-fluid mt-3"> 
    <div class="col-12">
      <br>
      <a class="brand" href="index.html">
        <img src="img/ipn.png"  class="mx-auto d-block imgassm">
      </a> 
   </div>
  </div>
  <br>
    <div class="container text-center">
      <nav  class="navbar navbar-expand-sm bg-white justify-content-center">
       <!--H <nav  class="navbar fixed-top navbar-expand-lg bg-dark fixed-top">-->
        <div class="row-12">
                <div class="collapse navbar-collapse col border-bottom " id="navbarContent">

                  <!-- <button type="button" class="btn btn-info btn-sm" id="btndiag"><small>DIAGÓSTICO DE<BR>PROCESO GRATIS</small></button>-->
                </div>    
        </div>
      </nav>
   </div> 
  </div>
<!--MOVIL-->
<div class="d-block d-sm-block d-md-none">
  <nav class="navbar navbar-expand-lg navbar-light bg-light">
    <a class="brand " href="index.html">
      <img src="img/ipn.png"  class="mx-auto d-block imgassmMo logo">
    </a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNavDropdown" aria-controls="navbarNavDropdown" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNavDropdown">

    </div>
  </nav>
</div>


<!--PÁRRAFO-->
<div class="container mt-3">
  <div class="row" >
   <div class="col-12 text-center">
      <h4><p class="frances h4"><strong>Sistema Analizador De Redes LAN de computadoras</strong></p></h4>
   </div>
  </div>
</div>
<br>





$table



$tablemac
$tablepuertos
$tablevuln
$tablafuzz
$tablawa

<br>
<br>
<br>
<br>
<!--FOOTER -->

<footer class=" bg-dark page-footer pt-2 " >

   <!-- Footer Links -->
   <div class="container-fluid">
   
   <!-- Copyright -->

   <div class="col-md-6 mx-auto text-center text-white mt-5">IPN ESIME Zacatenco Junio 2021 &copy; 

   </div>
  </div>  
  
   <!-- Copyright -->
 
 </footer>

 <!-- Footer -->

   <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
   </body>
</html>


EOF


echo "Aqui"


}



main (){

echo "main estoy adentro"
sweepPing $ip

if [[ $(cat ips.tmp | grep -io "0 hosts up") == "0 hosts up" ]]; then

	echo "0 host up"
	exit 1
fi	


osRecon
buscaPuertosAbiertos
deteccionServicios

if [[ $vulnerabilidades == "vsi" ]]; then

	#echo "Ejecutar escaneo de vulnerabilidades"
	scanVuln
	crearTablaVuln
	CrearNotificacion


else

	echo "NO ejecuta ningun escaneo de vulnerabilidades"

fi	


if [[ $fuzzer == "fsi" ]]; then

	#echo "Ejecutar escaneo de fuzing"
	fuzzgo
	#Crearwhat
    CrearFuzz
    crearTablaFuzz

else

	echo "NO ejecuta ningun escaneo de fuzzing" 

fi	


if [[ $httprecon == "rsi" ]]; then

	#echo "Ejecutar escaneo de whatweb"

	whatweb1
	Crearwhat
	crearTablaWhat

else

	echo "NO ejecuta ningun escaneo de whatweb"

fi


crearTablaIp
crearTablaPuertos


}




mainroot(){
	
echo "mainroot estoy adentro"
sweepPing $ip


if [[ $(cat ips.tmp | grep -io "0 hosts up") == "0 hosts up" ]]; then

	echo "0 host up"
#Mandar Evento de error
		
	exit 1
fi	

arpIP
osRecon
buscaPuertosAbiertos
deteccionServicios


if [[ $vulnerabilidades == "vsi" ]]; then

	echo "Ejecutar escaneo de vulnerabilidades"
	scanVuln
	crearTablaVuln
	CrearNotificacion
	cat noti.tmp

else

	echo "NO ejecuta ningun escaneo de vulnerabilidades"

fi	


if [[ $fuzzer == "fsi" ]]; then

	echo "Ejecutar escaneo de fuzing"
	fuzzgo
	#Crearwhat
	CrearFuzz
	crearTablaFuzz

else

	echo "NO ejecuta ningun escaneo de fuzzing" 

fi	


if [[ $httprecon == "rsi" ]]; then

	echo "Ejecutar escaneo de whatweb"
	whatweb1
	Crearwhat
	crearTablaWhat

else

	echo "NO ejecuta ningun escaneo de whatweb"

fi

crearTablaMAC
crearTablaIp
crearTablaPuertos

chmod  -R 777 servicios/*.html
chmod  -R 777 servicios/*.tmp
chmod  -R 777 vulnerabilidades/*.tmp
chmod  -R 777 vulnerabilidades/*.html
chmod  -R 777 reconocimientoweb/*.tmp
chmod  -R 777 reconocimientoweb/*.html
chmod  -R 777 fuzzeo/*.tmp
chmod  -R 777 *.html
chmod  -R 777 *.tmp

}


ip=$1
puertos=$2
vulnerabilidades=$3
fuzzer=$4
httprecon=$5

#sudo ./normalunaip.sh 192.168.0.3 puertost vno fno rno 
#sudo ./normal.sh 192.168.0.* puertostn vno fsi rno
echo "asfasd" > g.txt
rutas=$(pwd)
mkdir servicios
mkdir vulnerabilidades
mkdir fuzzeo
mkdir reconocimientoweb
rm -f *.tmp
rm -f *.xml
rm -f res.html
rm -f -R servicios/*.html
rm -f -R servicios/*.tmp
rm -f -R vulnerabilidades/*.tmp
rm -f -R vulnerabilidades/*.html
rm -f -R reconocimientoweb/*.tmp
rm -f -R reconocimientoweb/*.html
rm -f -R fuzzeo/*.tmp
rm -f ipmacvendor.tmp

rm -f tablapuertos.tmp
rm -f tablamac.tmp
rm -f tablaipyso.tmp
rm -f tablavuln.tmp
rm -f tablafuzz.tmp

#curl --noproxy localhost, -X POST --data "data=testControl,loadModels,start," http://localhost:8080/sendSocketMessage

if [ "$(id -u)" == "0" ]; then
	
	echo "Soy ROOT id -u = 0 " 
	mainroot

else
	echo "No soy root :"
	main

fi

tablemac=$(cat tablamac.tmp)
tablepuertos=$(cat tablapuertos.tmp)
tablevuln=$(cat tablavuln.tmp)
table=$(cat tablaipyso.tmp)
tablafuzz=$(cat tablafuzz.tmp)
tablawa=$(cat tablawhat.tmp)
tablanotificacion=$(cat noti.tmp)
CrearTablaMadre
rm -f *.tmp
rm -f servicios/*.tmp
rm -f reconocimientoweb/*.tmp
rm -f vulnerabilidades/*.tmp
rm -f fuzzeo/*.tmp

echo "1" > g.txt
echo "Guadando resultados"
dia=$(echo "Escaneo_$(date|tr ' ' '_')")
mkdir "${dia}"
cp res.html "${dia}"
cp -r servicios "${dia}"
cp -r reconocimientoweb "${dia}"
cp -r vulnerabilidades "${dia}"
cp -r fuzzeo "${dia}"
echo " en donde estoy "
#pwd > larutadondeestas.txt
