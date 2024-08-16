#include <stdio.h>
#include "automaton.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "cora.h"

// essa função recebe o automato recém alocado e os fast patterns que devem ser instalados no automato.
int build_automaton(struct fast_p* fast_patterns_array, size_t p_len, struct automaton *result) {

    char* fps[p_len];
	for(int i = 0; i < p_len; i++){
		fps[i] = fast_patterns_array[i].fp;
        // printf("%s\n", fps[i]);
	}

	// A partir daqui passa a contruir o automato
	struct node_array* aca = get_ac_automaton(fps, p_len);

	struct automaton_transition *transitions = malloc(sizeof(struct automaton_transition) * aca->array_size);
	int c = 0;

	for(int i = 0; i < aca->array_size; i++){
		for(int j = 0; j < S; j++){
			if(aca->array[i]->nxt[j] != -1){
				transitions[c].key_state = (uint16_t)i;
				transitions[c].key_transition = (uint8_t)TO_C(j);
				transitions[c].value_state = (uint16_t)aca->array[i]->nxt[j];
				transitions[c].value_leaf = (uint16_t)aca->array[aca->array[i]->nxt[j]]->leaf;
				
				if(aca->array[aca->array[i]->nxt[j]]->represents){
					char* pattern = aca->array[aca->array[i]->nxt[j]]->represents;
					transitions[c].fp__rule_index = -1;
					for(int k = 0; k < p_len; k++){
						if(!strcmp(pattern, fast_patterns_array[k].fp)){
							transitions[c].fp__rule_index = k;
							break;
						}
					}
				}
				c++;
			}
		}
	}
   
	result->size = aca->array_size;
	result->entries = transitions;
	free_automaton(aca);
	return 0;
}

// any;8300~/uu/frpc.tar.gz;50292~NM_A_SZ_TRANSACTION_ID;21915~/Mac/getInstallScript/;41460;clickid=,software=~/IMManager/Admin/IMAdminSystemDashboard.asp;21066;refreshRateSetting=~/online.php?c=;41331;&u=,&p=,&hi=~act=search;16614;submit=~NM_A_PARM1;21916~/gt.jpg?;37733;=,bytes=6433-~/post.php;40238;type=,hwid=,pcname=,username=,password=~/createsearch;29753;POST,cmd=0,val=,type=9~/ApmAdminServices/;35279;haid,Content-Disposition~/newera/walkthisland/greenland.php;39968~/proxy.cgi;46515;url=,%26~/appliancews/getLicense;40837;hostName=,%26~/sms.php?apelido=;53750;/controls/
