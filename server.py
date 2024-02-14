import matplotlib
matplotlib.use('TkAgg')  # backend apropriado para Tkinter

from flask import Flask, render_template, request, redirect, url_for
import os
from scapy.all import rdpcap, IP, TCP
from sklearn.ensemble import IsolationForest
from werkzeug.utils import secure_filename
import matplotlib.pyplot as plt
import base64
import io
from flask_socketio import SocketIO, emit
from collections import Counter

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
requests_data = []
socketio = SocketIO(app)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def analyze_requests_with_chart(requests):
    # Lógica de análise aqui
    total_requests = len(requests)

    # Adicione lógica para coletar informações ao longo do tempo
    time_points = [i * 10 for i in range(total_requests)]  # Exemplo: pontos de tempo a cada 10 requisições
    data_points = [total_requests - i for i in range(total_requests)]  # Exemplo: dados fictícios

    # Crie um gráfico de barras
    labels = ['GET', 'POST', 'PUT', 'DELETE']  # Adapte conforme necessário
    methods = ['GET', 'POST', 'PUT', 'DELETE']  # Substitua pelos métodos reais extraídos das requisições
    
    plt.bar(labels, methods)
    plt.xlabel('Método HTTP')
    plt.ylabel('Quantidade')
    plt.title('Distribuição de Métodos HTTP')

    # Salve a imagem em BytesIO
    image_stream = io.BytesIO()
    plt.savefig(image_stream, format='png')
    image_stream.seek(0)
    
    # Converta a imagem em base64 para incorporação no HTML
    image_base64 = base64.b64encode(image_stream.getvalue()).decode('utf-8')
    image_url = f'data:image/png;base64,{image_base64}'

    # Adicione outras análises conforme necessário
    return total_requests, image_url, time_points, data_points  # Novos valores retornados 

def detect_ddos(packets):
    total_packets = len(packets)
    if total_packets == 0:
        return "Baixo", "Tráfego Normal"

    packets_per_second = total_packets / packets[-1].time
    if packets_per_second > 50:  # Ajuste o limite conforme necessário
        ddos_likelihood = "Alto"
        attack_type = "Possível Ataque DDoS"
    else:
        ddos_likelihood = "Baixo"
        attack_type = "Tráfego Normal"

    return ddos_likelihood, attack_type

def detect_syn_flood_ip(packets):
    syn_packets = [packet for packet in packets if TCP in packet and packet[TCP].flags.S and not packet[TCP].flags.A]
    source_ips = [packet[IP].src for packet in syn_packets]
    
    # Identificar o IP mais frequente (pode ser o IP do atacante)
    most_common_ip = Counter(source_ips).most_common(1)

    if most_common_ip:
        return most_common_ip[0][0]
    else:
        return None

def detect_tcp_flood(packets, threshold=100):
    tcp_packets = [packet for packet in packets if 'TCP' in packet]
    total_tcp_packets = len(tcp_packets)
    
    if total_tcp_packets == 0:
        return "Baixo", "Tráfego Normal", None

    time_range = packets[-1].time - packets[0].time
    tcp_packets_per_second = total_tcp_packets / time_range

    flood_ip = None  # Inicializa a variável com None

    if tcp_packets_per_second > threshold:
        likelihood = "Alto"
        attack_type = "SYN TCP FLOOD"
        flood_ip = detect_syn_flood_ip(packets)  # Chama a função detect_syn_flood_ip para obter o IP
    else:
        likelihood = "Baixo"
        attack_type = "Tráfego Normal"

    return likelihood, attack_type, flood_ip

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['GET','POST'])
def upload():
    if request.method == 'POST':
        # Lógica para processar o upload...
        if 'file' not in request.files:
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            return redirect(request.url)

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(file_path)

        # Chame a função de análise da IA
        packets = rdpcap(file_path)
        tcp_likelihood, tcp_attack_type, flood_ip = detect_tcp_flood(packets, threshold=50)

        # Realize a análise final
        final_analysis = perform_final_analysis(packets, tcp_likelihood, tcp_attack_type, flood_ip, file)

        # Retorne uma página HTML com os resultados da análise
        return render_template('result.html', result=final_analysis)

    return render_template('upload.html')

def analyze_pcap(file_path, uploaded_file):
    # Implemente a lógica de análise usando o modelo de machine learning
    packets = rdpcap(file_path)
    file_name = secure_filename(uploaded_file.filename)

    # Exemplo: Verifique se há um número anormal de pacotes (pode indicar DDoS)
    total_packets = len(packets)
    if total_packets > 10000:
        ddos_likelihood = "Alto"
    else:
        ddos_likelihood = "Baixo"

    # Exemplo: Use o Isolation Forest para detectar anomalias nos dados dos pacotes
    data = [(len(packet),) for packet in packets]
    model = IsolationForest(contamination=0.01)
    model.fit(data)
    predictions = model.predict(data)
    
    # Se a maioria das predições for -1, isso pode indicar uma anomalia (ataque)
    if sum(predictions == -1) > 0.5 * len(predictions):
        attack_type = "Possível Ataque"
    else:
        attack_type = "Tráfego Normal"

    # Exemplo de obtenção de informações de pacotes
    packet_info = []
    handshake_count = 0

    for packet in packets:
        if IP in packet and TCP in packet:
            # Adicione lógica específica para identificar handshakes ou outros padrões
            if packet[TCP].flags.S and not packet[TCP].flags.A:
                handshake_count += 1

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            packet_info.append(f"IP Origem: {src_ip}, IP Destino: {dst_ip}, Porta Origem: {src_port}, Porta Destino: {dst_port}")

    # Construa uma lista de strings representando os resultados detalhados
    description = f"Neste arquivo, foram identificados {handshake_count} handshakes TCP."
    results = [
        f"Total de pacotes: {total_packets}, todos os pacotes do arquivo '{file_name}' foram minuciosamente analisados, revelando insights valiosos com base no tráfego contido.",
        f"Probabilidade de DDoS: {ddos_likelihood}",
        f"Tipo de Ataque DDoS: {attack_type}",
        "\n".join(packet_info) if packet_info else "N/A"
        # Adicione outras informações conforme necessário
        # ...
    ]

    # Retorne a lista de resultados
    return results

def perform_final_analysis(packets, tcp_likelihood, tcp_attack_type, flood_ip, uploaded_file):
    # Implemente a lógica de análise final aqui
    # Pode incluir uma análise geral com base nos resultados obtidos

    # Exemplo: Contagem total de pacotes
    total_packets = len(packets)
    file_name = secure_filename(uploaded_file.filename)

    # Adicione informações específicas sobre o tipo de ataque se detectado
    if tcp_likelihood == "Alto" and tcp_attack_type == "SYN TCP FLOOD":
        final_analysis = [
            f"Total de pacotes: {total_packets}, todos os pacotes do arquivo '{file_name}' foram minuciosamente analisados, revelando insights valiosos com base no tráfego contido.",
            f"{tcp_likelihood}, devido ao alto número de pacotes, há uma possibilidade significativa de um ataque DDoS. IP das Requests: {flood_ip}",
            f"{tcp_attack_type}, a análise identificou padrões consistentes com esse tipo de atividade devido a um alto número de requests TCP incompletos, aumentando a probabilidade de que o tráfego observado seja malicioso",
            "Análise Geral: Potencial Anomalia Detectada, os resultados indicam um volume de tráfego que pode indicar um possível ataque SYN TCP FLOOD."
        ]
    else:
        # Exemplo: Alguma consideração com base na contagem de pacotes
        if total_packets < 100:
            final_analysis = [
                f"Total de pacotes: {total_packets} todos os pacotes do arquivo '{file_name}' foram minuciosamente analisados, revelando insights valiosos com base no tráfego contido.",
                "Tráfego Leve após a análise dos pacotes. O tráfego analisado indica um volume relativamente baixo de atividade na rede.",
                "Os resultados indicam um volume de tráfego relativamente baixo, o que pode ser considerado normal.",
                "Análise Geral: Não foram identificadas anomalias significativas nos pacotes analisados."
            ]
        elif total_packets < 1000:
            final_analysis = [
                f"Total de pacotes: {total_packets}, todos os pacotes do arquivo '{file_name}' foram minuciosamente analisados, revelando insights valiosos com base no tráfego contido.",
                "Tráfego Moderado após a análise dos pacotes. O tráfego analisado indica uma atividade de rede em um nível moderado.",
                "O volume de tráfego está em um nível moderado, sugerindo uma atividade de rede estável.",
                "Análise Geral: Não foram detectados padrões de tráfego anormais nos pacotes analisados."
            ]
        else:
            final_analysis = [
                f"Total de pacotes: {total_packets}, todos os pacotes do arquivo '{file_name}' foram minuciosamente analisados, revelando insights valiosos com base no tráfego contido.",
                "Tráfego Intenso após a análise dos pacotes. O tráfego analisado indica uma alta atividade na rede, não encontrado padrões que indicam a possibilidade de ataque DDoS.",
                "O volume de tráfego é substancial, indicando uma alta atividade na rede. É importante ressaltar que, neste momento, não há indícios ou sinais de um ataque DDoS (Distributed Denial of Service) em andamento.",
                "Análise Geral: Não foram observadas anomalias críticas nos padrões de tráfego analisados."
            ]

    return final_analysis

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    total_requests, chart_image_url, _, _ = analyze_requests_with_chart(requests_data)
    emit('update', {'data': f'Total de Requisições: {total_requests}', 'chart_image_url': chart_image_url})

if __name__ == '__main__':
    socketio.run(app, debug=True)
