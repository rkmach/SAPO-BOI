import os

tcp_port_pair = {}
udp_port_pair = {}
ignored_rules = []

seen_sids = []
processed_rules = 0

var_ports = {
        b'$HTTP_PORTS': b'[36,80,81,82,83,84,85,86,87,88,89,90,311,383,555,591,593,631,801,808,818,901,972,1158,1220,1414,1533,1741,1830,1942,2231,2301,2381,2809,2980,3029,3037,3057,3128,3443,3702,4000,4343,4848,5000,5117,5250,5600,6080,6173,6988,7000,7001,7071,7144,7145,7510,7770,7777,7778,7779,8000,8008,8014,8028,8080,8081,8082,8085,8088,8090,8118,8123,8180,8181,8222,8243,8280,8300,8333,8344,8500,8509,8800,8888,8899,8983,9000,9060,9080,9090,9091,9111,9290,9443,9999,10000,11371,12601,13014,15489,29991,33300,34412,34443,34444,41080,44449,50000,50002,51423,53331,55252,55555,56712]',
        b'$SSH_PORTS': b'22'
        }


def parse_content_options (options):
    # bitmap:
    # fastpattern nocase depth offset distance within
    bitmap = 0
    new_options = b''
    if b'fast_pattern' in options:
        bitmap |= 1 << 5
    if b'nocase' in options:
        bitmap |= 1 << 4
    if b'depth' in options:
        bitmap |= 1 << 3
    if b'offset' in options:
        bitmap |= 1 << 2
    if b'distance' in options:
        bitmap |= 1 << 1
    if b'within' in options:
        bitmap |= 1

    options_array = options.split (b',')
    for option in options_array:
        if b'fast_pattern' in option:
            bitmap |= 1 << 5
        if b'nocase' in option:
            bitmap |= 1 << 4
        if b'depth' in option:
            bitmap |= 1 << 3
            if (new_options != b''):
                new_options += b' '
            new_options += option.split (b' ')[1]
        if b'offset' in option:
            bitmap |= 1 << 2
            if (new_options != b''):
                new_options += b' '
            new_options += option.split (b' ')[1]
        if b'distance' in option:
            bitmap |= 1 << 1
            if (new_options != b''):
                new_options += b' '
            new_options += option.split (b' ')[1]
        if b'within' in option:
            bitmap |= 1
            if (new_options != b''):
                new_options += b' '
            new_options += option.split (b' ')[1]

    return (bitmap, new_options)


def contents_to_byte (contents):
    if len(contents) == 0:
        return {}
    sid = list(contents.keys())[0]
    ret = {sid:[]}
    for content in contents[sid]:
        splited_content = content.split(b'"')
        pure_content = splited_content[1]
        
        state = 0
        c = 0
        cur_content = b''
        while c < len (pure_content):
            if state == 0:
                if pure_content[c] == 124: #124 == '|'
                    state = 1
                    c += 1
                    continue
                cur_content += bytes([pure_content[c]])
                c += 1
            if state == 1:
                if pure_content[c] == 0x20: #0x20 == ' '
                    c += 1
                    continue
                if pure_content[c] == 124:
                    state = 0
                    c += 1
                    continue
                value_string = pure_content[c:c+2]
                value_int = int (value_string,16)
                cur_content += bytes([value_int])
                c += 2
        new_content = []
        new_content.append(cur_content)
        new_content.append(splited_content[2])
        ret[sid].append(new_content)

    return ret



def get_layer4_protocol_by_rule (rule):
    rule = rule.split (b' ')
    return rule[1]

def get_ports_by_rule (rule):
    src_port = b''
    dst_port = b''
    rule = rule.split (b' ')
    for j in range (len(rule)):
        if rule[j] == b'->' or rule[j] == b'<>':
            src_port = rule[j - 1]
        elif rule [j] == b'(':
            dst_port = rule[j - 1]
    if src_port != b'':
        return (src_port, dst_port)
    return (b'', b'')

def get_contents_by_rule (rule):
    ret = {}
    sid =b''

    rule = rule.split (b';')

    for i in range (len(rule)):
        if b'sid:' in rule[i]:
            sid = rule[i].replace(b' sid:',b'')
            if sid not in seen_sids:
                seen_sids.append(sid)
            else:
                print(f"sid {sid} já foi analisado!!!!!!")
                return {}
            break

    ret[sid] = []
    for i in range (len(rule)):
        if b'content:' in rule[i]:
            ret[sid].append(rule[i].replace(b' content:', b''))

    if ret[sid] == []:
        return {}
    return ret



def parse_variable_ports (ports):
    for i in range (len(ports)):
        for k in var_ports:
            if b'[' in ports[i]:
                ports[i] = ports[i].replace(k,var_ports[k].strip(b'[').strip(b']'))
            else:
                ports[i] = ports[i].replace(k,var_ports[k])
    

def remove_useless_brackets (ports):
    for i in range (len(ports)):
        if b',' not in ports[i] and b'[' in ports[i]:
            ports[i] = ports[i].strip(b'[').strip(b']')
            

def load_rules (file_name):
    global processed_rules
    f_in = open (file_name, 'rb')
    for i in f_in:
        if not i.startswith(b'alert'):
            continue
        ports = get_ports_by_rule(i)
        contents = get_contents_by_rule(i)
        contents = contents_to_byte (contents)
        protocol = get_layer4_protocol_by_rule (i)
        if ports == (b'',b'') or contents == {}:
            continue

        processed_rules += 1
        if protocol == b'tcp':
            if ports not in tcp_port_pair:
                tcp_port_pair[ports] = [contents]
            else:
                tcp_port_pair[ports].append(contents)
        elif protocol == b'udp':
            if ports not in udp_port_pair:
                udp_port_pair[ports] = [contents]
            else:
                udp_port_pair[ports].append(contents)
        else:
            ignored_rules.append(contents)
        

def flush_rules():
    f_tcp = open ('sapo_boi_tcp_rules.perereca', 'wb')
    for port_pair in tcp_port_pair:
        f_tcp.write (port_pair[0] + b'\n')
        f_tcp.write (port_pair [1] + b'\n')
        
        f_tcp.write (b'%d\n' % len(tcp_port_pair[port_pair]))
       
        current_rule_set = tcp_port_pair[port_pair]
        for rule in current_rule_set:
            sid = list(rule.keys())[0]
            f_tcp.write (sid + b'\n')
            f_tcp.write (b'%d\n'  % len(rule[sid]))

            for content in rule[sid]:
                f_tcp.write (b'%d\n' % len(content[0]))
                f_tcp.write (content[0] + b'\n')
                options_tuple = parse_content_options (content[1])
                f_tcp.write (b'%d' % options_tuple[0] + b'\n')
                f_tcp.write (options_tuple[1] + b'\n')
    f_tcp.close()

    f_udp = open ('sapo_boi_udp_rules.perereca', 'wb')
    for port_pair in udp_port_pair:
        f_udp.write (port_pair[0] + b'\n')
        f_udp.write (port_pair [1] + b'\n')
        
        f_udp.write (b'%d\n' % len(udp_port_pair[port_pair]))
       
        current_rule_set = udp_port_pair[port_pair]
        for rule in current_rule_set:
            sid = list(rule.keys())[0]
            f_udp.write (sid + b'\n')
            f_udp.write (b'%d\n'  % len(rule[sid]))

            for content in rule[sid]:
                f_udp.write (b'%d\n' % len(content[0]))
                f_udp.write (content[0] + b'\n')
                options_tuple = parse_content_options (content[1])
                f_udp.write (b'%d' % options_tuple[0] + b'\n')
                f_udp.write (options_tuple[1] + b'\n')
    f_udp.close()


if __name__ == "__main__":
    processed_rules = 0
    #load_rules('snort3-community.rules')
    # *************************************************MUDAR**********************************************
    rules_dir = "rules/"
    for file in os.listdir(rules_dir):
        if file.endswith(".rules"):
           load_rules(os.path.join(rules_dir, file))

    print(f"\nForam processadas {processed_rules} regras!!\n")
    flush_rules()


    '''
    for i in udp_port_pair:
        print (str(i) + ': ' + str(udp_port_pair[i]))
        print ()
    '''
