import os
import sys
import re
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from pymongo import MongoClient
from netmiko import ConnectHandler
from pyzabbix import ZabbixAPI

# Configura os caminhos para os arquivos de log e adiciona um handler para rotação de logs
log_file_path = 'backup_log.log'

# Deleta o arquivo de log se ele existir
if os.path.exists(log_file_path):
    os.remove(log_file_path)
    
logger = logging.getLogger('BackupLogger')
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(log_file_path, maxBytes=5*1024*1024, backupCount=5)
stdout_handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
handler.setFormatter(formatter)
stdout_handler.setFormatter(formatter)
logger.addHandler(handler)
logger.addHandler(stdout_handler)

# Configuração da conexão com o MongoDB
client = MongoClient('mongodb://127.0.0.1:27017/')
db = client['db']  # Substitua pelo nome do seu banco de dados real
backup_collection = db.automacaobackup

DEFAULT_USERNAME = 'user'
DEFAULT_PASSWORD = 'pass'

# Defina as credenciais para dispositivos Ubiquiti
UBIQUITI_USERNAME = 'user'
UBIQUITI_PASSWORD = 'pass'

# Diretório para armazenar os backups
BACKUP_FOLDER = 'backup'


zabbix_server = "http://0.0.0.0/zabbix/api_jsonrpc.php" 
zabbix_username = "user"  
zabbix_password = "pass"  
try:
    zapi = ZabbixAPI(zabbix_server)
    zapi.login(zabbix_username, zabbix_password)
    version = zapi.api_version()
    #logger.info(f"Conexão bem-sucedida! Versão da API do Zabbix: {version}")
except Exception as e:
    logger.error(f"Erro ao conectar-se ao Zabbix: {e}")

def perform_backup():

    # Exclui arquivos antigos antes de iniciar novos backups
    excluir_arquivos_antigos(BACKUP_FOLDER, 30)  # Ajuste o número de dias conforme necessário

   # Busca os equipamentos que precisam de backup
    try:
        equipment_to_backup = backup_collection.find()
    except Exception as e:
        logger.error(f"Erro ao buscar equipamentos para backup: {e}")
        return

    for equipment in equipment_to_backup:
        # Verifica se a chave 'hostid' existe no documento
        if 'hostid' not in equipment:
            logger.error("Documento de equipamento encontrado sem 'hostid'. Pulando este documento.")
            continue
        hostid = equipment['hostid']

        try:
            host_info = zapi.host.get(
                output=["hostid", "name"],
                filter={"hostid": hostid},
                selectInterfaces=["ip"]
            )[0]

            if not host_info:
                logger.error(f"Nenhum host encontrado com o hostid {hostid}")
                continue

            nome = host_info['name']
            ip = host_info['interfaces'][0]['ip'] if host_info['interfaces'] else None

            if not ip:
                logging.error(f"IP do host {nome} não encontrado")
                continue

            itens = zapi.item.get(
                output=['key_', 'lastvalue'],
                hostids=hostid
            )
        except Exception as e:
            logger.error(f"Erro ao obter informações do host com hostid {hostid}: {e}")
            continue

        # Inicializa variáveis para extensão de arquivo e comando
        file_extension = ''
        backup_command = ''

        disponibilidade = None
        username = DEFAULT_USERNAME
        password = DEFAULT_PASSWORD
        for item in itens:
            if item['key_'] == 'system.descr[sysDescr.0]':
                if 'Juniper' in item['lastvalue']:
                    device_type = 'juniper'
                    backup_command = 'show configuration | display set'
                    file_extension = '.conf'  # Sugerido para Juniper
                elif 'DmOS' in item['lastvalue']:
                    device_type = 'cisco_ios'
                    backup_command = 'show running-config | nomore'
                    file_extension = ''  # Sem extensão
                elif 'Huawei' in item['lastvalue']:
                    device_type = 'huawei'
                    backup_command = 'display current-configuration'
                    file_extension = ''  # Sem extensão
                elif 'RouterOS' in item['lastvalue']:
                    device_type = 'mikrotik_routeros'
                    backup_command = 'export'
                    file_extension = '.rsc'  # Extensão para MikroTik
                elif 'Linux' in item['lastvalue']:
                    device_type = 'ubiquiti_edge'
                    backup_command = 'cat /tmp/system.cfg'
                    file_extension = '.cfg'  # Assumindo que a extensão para backup do Ubiquiti seja .cfg 
                    username = UBIQUITI_USERNAME
                    password = UBIQUITI_PASSWORD
            elif item['key_'] == 'icmpping':
                print(item['key_'])
                disponibilidade = 'disponivel' if item['lastvalue'] == '1' else 'indisponivel'

        # Verifica a disponibilidade antes de prosseguir
        if disponibilidade != 'disponivel':
            error_message = f"Dispositivo {nome} ({ip}) não está disponível para backup."
            logger.error(error_message)
            continue  # Em vez de levantar uma exceção, apenas continue para o próximo dispositivo

        nome = host_info['name']     
        print(username)
        print(password)
        device = {
            'device_type': device_type,
            'host': ip,
            'username': username,
            'password': password,
            'port': 22,  # porta padrão SSH
            'global_delay_factor': 2,
        }

        try:
            with ConnectHandler(**device) as net_connect:
                backup = net_connect.send_command(backup_command, delay_factor=2, read_timeout=300)
                filename = f"{nome}-{datetime.now().strftime('%d%m%Y-%H%M')}{file_extension}"
                file_path = os.path.join(BACKUP_FOLDER, filename)

                with open(file_path, 'w') as file:
                    file.write(backup)
                logger.info(f"Backup realizado com sucesso para {nome}")

        except Exception as e:
            logger.error(f"Falha ao realizar backup de {nome}: {e}")
            continue 

def excluir_arquivos_antigos(diretorio, dias=30):
    """
    Exclui arquivos mais antigos que 'dias' no diretório especificado.
    Utiliza expressões regulares para extrair a data do nome do arquivo.
    """
    agora = datetime.now()
    padrao_data = re.compile(r'(\d{8}-\d{4})')  # Corresponde a 'DDMMYYYY-HHMM'

    for arquivo in os.listdir(diretorio):
        try:
            # Procura pela data no nome do arquivo usando expressões regulares
            resultado_busca = padrao_data.search(arquivo)
            if resultado_busca:
                data_arquivo_str = resultado_busca.group(1)
                data_arquivo = datetime.strptime(data_arquivo_str, '%d%m%Y-%H%M')

                # Calcula a diferença em dias
                if agora - data_arquivo > timedelta(days=dias):
                    caminho_completo = os.path.join(diretorio, arquivo)
                    os.remove(caminho_completo)
                    logger.info(f"Arquivo excluído por ser mais antigo que {dias} dias: {arquivo}")
            else:
                logger.error(f"Não foi possível encontrar a data no nome do arquivo: {arquivo}")
        except Exception as e:
            logger.error(f"Erro ao tentar excluir {arquivo}: {e}")

if __name__ == '__main__':
    perform_backup()
