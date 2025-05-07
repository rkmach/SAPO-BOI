import sys
import numpy
import os

tcp_port_groups = {}
udp_port_groups = {}

def extract_rule_header(string: str):
    start = string.find('->')
    first_part = string[0:start-1].split(' ')
    proto = first_part[1]
    src_port = first_part[3]

    end = string.find('(')
    second_part = string[start+3:end-1].split(' ')
    dst_port = second_part[1]

    return proto, src_port, dst_port

def extrair_opcoes_content(string:str):
    inicio_content = string.find("content:")
    if inicio_content == -1:
        return
    opcoes_content = []
    fast_pattern = None
    while inicio_content != -1:
        inicio_valor = string.find('"', inicio_content) + 1
        fim_valor = string.find('"', inicio_valor)
        opcao_content = string[inicio_valor:fim_valor]
        fim_content = string.find(";", fim_valor)
        if "fast_pattern" in string[fim_valor:fim_content]:
            fast_pattern = opcao_content
        else:
            opcoes_content.append(opcao_content)
        inicio_content = string.find("content:", fim_valor)
    
    if not fast_pattern:
        fast_pattern = max(opcoes_content, key=len)
        opcoes_content.remove(fast_pattern)
    sid_inicio = string.find("sid:") + 4
    sid_fim = string.find(';', sid_inicio)
    #return fast_pattern, opcoes_content, string[sid_inicio:sid_fim]
    #print(fast_pattern)
    return fast_pattern

if __name__ == "__main__":

    rules_dir = "rules/"
    fps = []
    treze = 0
    for file in os.listdir(rules_dir):
        if file.endswith(".rules"):
            file = open(rules_dir + file, "r")

            for line in file:
                if line and line.startswith('alert'):
                    #protocol, src, dst = extract_rule_header(line)
                    #fast_pattern, patterns, sid = extrair_opcoes_content(line)
                    fast_pattern = extrair_opcoes_content(line)
                    if fast_pattern:
                        if '|' in fast_pattern:
                            x = fast_pattern.count(' ') + 1
                        else:
                            x = len(fast_pattern)
                        if(x >= 13):
                            treze+=1
                        fps.append(x)
                    #if len(fast_pattern) <= 13:
                    #    continue

    print(f"média = {numpy.mean(fps)}")
    print(f"treze = {treze}")

