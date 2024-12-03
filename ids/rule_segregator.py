import os

seen_sids = []


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
                        dst_port = rule[j - 1];
        if src_port != b'':
                return (src_port, dst_port)
        return (b'', b'')

def get_contents_by_rule (rule):
        ret = {}
        sid =b''

        rule = rule.split (b';')

        for i in range (len(rule)):
                if b' sid:' in rule[i]:
                        sid = rule[i].replace(b' sid:',b'')
                        if sid not in seen_sids:
                                seen_sids.append(sid)
                        else:
                                return {}
                        break

        ret[sid] = []
        for i in range (len(rule)):
                if b'content:' in rule[i]:
                        ret[sid].append(rule[i].replace(b' content:', b''))

        if ret[sid] == []:
                return {}
        return ret




def load_rules (file_name):
        f_out = open ("segregated.rules", "ab")
        f_in = open (file_name, 'rb')
        for i in f_in:
                if not i.startswith(b'alert'):
                        continue
                ports = get_ports_by_rule(i)
                if b"!" in ports[0] or b":" in ports[0] or b"!" in ports[1] or b":" in ports[1]:
                        continue

                protocol = get_layer4_protocol_by_rule (i)
                if ports == (b'',b''):
                        continue


                if protocol != b'tcp' and protocol != b'udp':
                        continue

                if not b"content:" in i:
                        continue

                if b"content:!" in i:
                        continue

                contents = get_contents_by_rule(i)
                contents = contents_to_byte (contents)

                key = contents.keys()
                largest_content = 0
                fp = 0
                for cur_content in contents[list(key)[0]]:
                        if (len (cur_content[0]) > largest_content) and not fp:
                                largest_content = len (cur_content[0]);

                        if b"fast_pattern" in cur_content[1]:
                                largest_content = len (cur_content[0]);
                                fp = 1

                if largest_content < 13:
                        continue

                f_out.write (i)

        f_out.close()
        f_in.close()


if __name__ == "__main__":
        rules_dir = "../rules/"
        for file in os.listdir(rules_dir):
                if file.endswith(".rules"):
                   load_rules(os.path.join(rules_dir, file))
