#ifndef MAPS_H
#define MAPS_H

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_AF_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

#define PORT_RANGE 65536
#define MAP_SIZE 65536
#define TAIL_CALL_MAP_SIZE 2

struct ids_map {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAP_SIZE);
        __type(key, struct automaton_map_key);
        __type(value, struct automaton_map_value);
} ids_map0 SEC(".maps"), ids_map1 SEC(".maps"), ids_map2 SEC(".maps"), \
ids_map3 SEC(".maps"), ids_map4 SEC(".maps"), ids_map5 SEC(".maps"), \
ids_map6 SEC(".maps"), ids_map7 SEC(".maps"), ids_map8 SEC(".maps"), \
ids_map9 SEC(".maps"), ids_map10 SEC(".maps"), ids_map11 SEC(".maps"), \
ids_map12 SEC(".maps"), ids_map13 SEC(".maps"), ids_map14 SEC(".maps"), \
ids_map15 SEC(".maps"), ids_map16 SEC(".maps"), ids_map17 SEC(".maps"), \
ids_map18 SEC(".maps"), ids_map19 SEC(".maps"), ids_map20 SEC(".maps"), \
ids_map21 SEC(".maps"), ids_map22 SEC(".maps"), ids_map23 SEC(".maps"), \
ids_map24 SEC(".maps"), ids_map25 SEC(".maps"), ids_map26 SEC(".maps"), \
ids_map27 SEC(".maps"), ids_map28 SEC(".maps"), ids_map29 SEC(".maps"), \
ids_map30 SEC(".maps"), ids_map31 SEC(".maps"), ids_map32 SEC(".maps"), \
ids_map33 SEC(".maps"), ids_map34 SEC(".maps"), ids_map35 SEC(".maps"), \
ids_map36 SEC(".maps"), ids_map37 SEC(".maps"), ids_map38 SEC(".maps"), \
ids_map39 SEC(".maps"), ids_map40 SEC(".maps"), ids_map41 SEC(".maps"), \
ids_map42 SEC(".maps"), ids_map43 SEC(".maps"), ids_map44 SEC(".maps"), \
ids_map45 SEC(".maps"), ids_map46 SEC(".maps"), ids_map47 SEC(".maps"), \
ids_map48 SEC(".maps"), ids_map49 SEC(".maps"), ids_map50 SEC(".maps"), \
ids_map51 SEC(".maps"), ids_map52 SEC(".maps"), ids_map53 SEC(".maps"), \
ids_map54 SEC(".maps"), ids_map55 SEC(".maps"), ids_map56 SEC(".maps"), \
ids_map57 SEC(".maps"), ids_map58 SEC(".maps"), ids_map59 SEC(".maps"), \
ids_map60 SEC(".maps"), ids_map61 SEC(".maps"), ids_map62 SEC(".maps"), \
ids_map63 SEC(".maps"), ids_map64 SEC(".maps"), ids_map65 SEC(".maps"), \
ids_map66 SEC(".maps"), ids_map67 SEC(".maps"), ids_map68 SEC(".maps"), \
ids_map69 SEC(".maps"), ids_map70 SEC(".maps"), ids_map71 SEC(".maps"), \
ids_map72 SEC(".maps"), ids_map73 SEC(".maps"), ids_map74 SEC(".maps"), \
ids_map75 SEC(".maps"), ids_map76 SEC(".maps"), ids_map77 SEC(".maps"), \
ids_map78 SEC(".maps"), ids_map79 SEC(".maps"), ids_map80 SEC(".maps"), \
ids_map81 SEC(".maps"), ids_map82 SEC(".maps"), ids_map83 SEC(".maps"), \
ids_map84 SEC(".maps"), ids_map85 SEC(".maps"), ids_map86 SEC(".maps"), \
ids_map87 SEC(".maps"), ids_map88 SEC(".maps"), ids_map89 SEC(".maps"), \
ids_map90 SEC(".maps"), ids_map91 SEC(".maps"), ids_map92 SEC(".maps"), \
ids_map93 SEC(".maps"), ids_map94 SEC(".maps"), ids_map95 SEC(".maps"), \
ids_map96 SEC(".maps"), ids_map97 SEC(".maps"), ids_map98 SEC(".maps"), \
ids_map99 SEC(".maps"), ids_map100 SEC(".maps"), ids_map101 SEC(".maps"), \
ids_map102 SEC(".maps"), ids_map103 SEC(".maps"), ids_map104 SEC(".maps"), \
ids_map105 SEC(".maps"), ids_map106 SEC(".maps"), ids_map107 SEC(".maps"), \
ids_map108 SEC(".maps"), ids_map109 SEC(".maps"), ids_map110 SEC(".maps"), \
ids_map111 SEC(".maps"), ids_map112 SEC(".maps"), ids_map113 SEC(".maps"), \
ids_map114 SEC(".maps"), ids_map115 SEC(".maps"), ids_map116 SEC(".maps"), \
ids_map117 SEC(".maps"), ids_map118 SEC(".maps"), ids_map119 SEC(".maps"), \
ids_map120 SEC(".maps"), ids_map121 SEC(".maps"), ids_map122 SEC(".maps"), \
ids_map123 SEC(".maps"), ids_map124 SEC(".maps"), ids_map125 SEC(".maps"), \
ids_map126 SEC(".maps"), ids_map127 SEC(".maps"), ids_map128 SEC(".maps"), \
ids_map129 SEC(".maps"), ids_map130 SEC(".maps"), ids_map131 SEC(".maps"), \
ids_map132 SEC(".maps"), ids_map133 SEC(".maps"), ids_map134 SEC(".maps"), \
ids_map135 SEC(".maps"), ids_map136 SEC(".maps"), ids_map137 SEC(".maps"), \
ids_map138 SEC(".maps"), ids_map139 SEC(".maps"), ids_map140 SEC(".maps"), \
ids_map141 SEC(".maps"), ids_map142 SEC(".maps"), ids_map143 SEC(".maps"), \
ids_map144 SEC(".maps"), ids_map145 SEC(".maps"), ids_map146 SEC(".maps"), \
ids_map147 SEC(".maps"), ids_map148 SEC(".maps"), ids_map149 SEC(".maps"), \
ids_map150 SEC(".maps"), ids_map151 SEC(".maps"), ids_map152 SEC(".maps"), \
ids_map153 SEC(".maps"), ids_map154 SEC(".maps"), ids_map155 SEC(".maps"), \
ids_map156 SEC(".maps"), ids_map157 SEC(".maps"), ids_map158 SEC(".maps"), \
ids_map159 SEC(".maps"), ids_map160 SEC(".maps"), ids_map161 SEC(".maps"), \
ids_map162 SEC(".maps"), ids_map163 SEC(".maps"), ids_map164 SEC(".maps"), \
ids_map165 SEC(".maps"), ids_map166 SEC(".maps"), ids_map167 SEC(".maps"), \
ids_map168 SEC(".maps"), ids_map169 SEC(".maps"), ids_map170 SEC(".maps"), \
ids_map171 SEC(".maps"), ids_map172 SEC(".maps"), ids_map173 SEC(".maps"), \
ids_map174 SEC(".maps"), ids_map175 SEC(".maps"), ids_map176 SEC(".maps"), \
ids_map177 SEC(".maps"), ids_map178 SEC(".maps"), ids_map179 SEC(".maps"), \
ids_map180 SEC(".maps"), ids_map181 SEC(".maps"), ids_map182 SEC(".maps"), \
ids_map183 SEC(".maps"), ids_map184 SEC(".maps"), ids_map185 SEC(".maps"), \
ids_map186 SEC(".maps"), ids_map187 SEC(".maps"), ids_map188 SEC(".maps"), \
ids_map189 SEC(".maps"), ids_map190 SEC(".maps"), ids_map191 SEC(".maps"), \
ids_map192 SEC(".maps"), ids_map193 SEC(".maps"), ids_map194 SEC(".maps"), \
ids_map195 SEC(".maps"), ids_map196 SEC(".maps"), ids_map197 SEC(".maps"), \
ids_map198 SEC(".maps"), ids_map199 SEC(".maps"), ids_map200 SEC(".maps"),
ids_map201 SEC(".maps"), ids_map202 SEC(".maps"), ids_map203 SEC(".maps"), \
ids_map204 SEC(".maps"), ids_map205 SEC(".maps"), ids_map206 SEC(".maps"), \
ids_map207 SEC(".maps"), ids_map208 SEC(".maps"), ids_map209 SEC(".maps"), \
ids_map210 SEC(".maps"), ids_map211 SEC(".maps"), ids_map212 SEC(".maps"), \
ids_map213 SEC(".maps"), ids_map214 SEC(".maps"), ids_map215 SEC(".maps"), \
ids_map216 SEC(".maps"), ids_map217 SEC(".maps"), ids_map218 SEC(".maps"), \
ids_map219 SEC(".maps"), ids_map220 SEC(".maps"), ids_map221 SEC(".maps"), \
ids_map222 SEC(".maps"), ids_map223 SEC(".maps"), ids_map224 SEC(".maps"), \
ids_map225 SEC(".maps"), ids_map226 SEC(".maps"), ids_map227 SEC(".maps"), \
ids_map228 SEC(".maps"), ids_map229 SEC(".maps"), ids_map230 SEC(".maps"), \
ids_map231 SEC(".maps"), ids_map232 SEC(".maps"), ids_map233 SEC(".maps"), \
ids_map234 SEC(".maps"), ids_map235 SEC(".maps"), ids_map236 SEC(".maps"), \
ids_map237 SEC(".maps"), ids_map238 SEC(".maps"), ids_map239 SEC(".maps"), \
ids_map240 SEC(".maps"), ids_map241 SEC(".maps"), ids_map242 SEC(".maps"), \
ids_map243 SEC(".maps"), ids_map244 SEC(".maps"), ids_map245 SEC(".maps"), \
ids_map246 SEC(".maps"), ids_map247 SEC(".maps"), ids_map248 SEC(".maps"), \
ids_map249 SEC(".maps"), ids_map250 SEC(".maps"), ids_map251 SEC(".maps"), \
ids_map252 SEC(".maps"), ids_map253 SEC(".maps"), ids_map254 SEC(".maps");
/*
ids_map255 SEC(".maps"), ids_map256 SEC(".maps"), ids_map257 SEC(".maps"), \
ids_map258 SEC(".maps"), ids_map259 SEC(".maps"), ids_map260 SEC(".maps"), \
ids_map261 SEC(".maps"), ids_map262 SEC(".maps"), ids_map263 SEC(".maps"), \
ids_map264 SEC(".maps"), ids_map265 SEC(".maps"), ids_map266 SEC(".maps"), \
ids_map267 SEC(".maps"), ids_map268 SEC(".maps"), ids_map269 SEC(".maps"), \
ids_map270 SEC(".maps"), ids_map271 SEC(".maps"), ids_map272 SEC(".maps"), \
ids_map273 SEC(".maps"), ids_map274 SEC(".maps"), ids_map275 SEC(".maps"), \
ids_map276 SEC(".maps"), ids_map277 SEC(".maps"), ids_map278 SEC(".maps"), \
ids_map279 SEC(".maps"), ids_map280 SEC(".maps"), ids_map281 SEC(".maps"), \
ids_map282 SEC(".maps"), ids_map283 SEC(".maps"), ids_map284 SEC(".maps"), \
ids_map285 SEC(".maps"), ids_map286 SEC(".maps"), ids_map287 SEC(".maps"), \
ids_map288 SEC(".maps"), ids_map289 SEC(".maps"), ids_map290 SEC(".maps"), \
ids_map291 SEC(".maps"), ids_map292 SEC(".maps"), ids_map293 SEC(".maps"), \
ids_map294 SEC(".maps"), ids_map295 SEC(".maps"), ids_map296 SEC(".maps"), \
ids_map297 SEC(".maps"), ids_map298 SEC(".maps"), ids_map299 SEC(".maps"), \
ids_map300 SEC(".maps"), ids_map301 SEC(".maps"), ids_map302 SEC(".maps"), \
ids_map303 SEC(".maps"), ids_map304 SEC(".maps"), ids_map305 SEC(".maps"), \
ids_map306 SEC(".maps"), ids_map307 SEC(".maps"), ids_map308 SEC(".maps"), \
ids_map309 SEC(".maps"), ids_map310 SEC(".maps"), ids_map311 SEC(".maps"), \
ids_map312 SEC(".maps"), ids_map313 SEC(".maps"), ids_map314 SEC(".maps"), \
ids_map315 SEC(".maps"), ids_map316 SEC(".maps"), ids_map317 SEC(".maps"), \
ids_map318 SEC(".maps"), ids_map319 SEC(".maps"), ids_map320 SEC(".maps"), \
ids_map321 SEC(".maps"), ids_map322 SEC(".maps"), ids_map323 SEC(".maps"), \
ids_map324 SEC(".maps"), ids_map325 SEC(".maps"), ids_map326 SEC(".maps"), \
ids_map327 SEC(".maps"), ids_map328 SEC(".maps"), ids_map329 SEC(".maps"), \
ids_map330 SEC(".maps"), ids_map331 SEC(".maps"), ids_map332 SEC(".maps"), \
ids_map333 SEC(".maps"), ids_map334 SEC(".maps"), ids_map335 SEC(".maps"), \
ids_map336 SEC(".maps"), ids_map337 SEC(".maps"), ids_map338 SEC(".maps"), \
ids_map339 SEC(".maps"), ids_map340 SEC(".maps"), ids_map341 SEC(".maps"), \
ids_map342 SEC(".maps"), ids_map343 SEC(".maps"), ids_map344 SEC(".maps"), \
ids_map345 SEC(".maps"), ids_map346 SEC(".maps"), ids_map347 SEC(".maps"), \
ids_map348 SEC(".maps"), ids_map349 SEC(".maps"), ids_map350 SEC(".maps"), \
ids_map351 SEC(".maps"), ids_map352 SEC(".maps"), ids_map353 SEC(".maps"), \
ids_map354 SEC(".maps"), ids_map355 SEC(".maps"), ids_map356 SEC(".maps"), \
ids_map357 SEC(".maps"), ids_map358 SEC(".maps"), ids_map359 SEC(".maps"), \
ids_map360 SEC(".maps"), ids_map361 SEC(".maps"), ids_map362 SEC(".maps"), \
ids_map363 SEC(".maps"), ids_map364 SEC(".maps"), ids_map365 SEC(".maps"), \
ids_map366 SEC(".maps"), ids_map367 SEC(".maps"), ids_map368 SEC(".maps"), \
ids_map369 SEC(".maps"), ids_map370 SEC(".maps"), ids_map371 SEC(".maps"), \
ids_map372 SEC(".maps"), ids_map373 SEC(".maps"), ids_map374 SEC(".maps"), \
ids_map375 SEC(".maps"), ids_map376 SEC(".maps"), ids_map377 SEC(".maps"), \
ids_map378 SEC(".maps"), ids_map379 SEC(".maps"), ids_map380 SEC(".maps"), \
ids_map381 SEC(".maps"), ids_map382 SEC(".maps"), ids_map383 SEC(".maps"), \
ids_map384 SEC(".maps"), ids_map385 SEC(".maps"), ids_map386 SEC(".maps"), \
ids_map387 SEC(".maps"), ids_map388 SEC(".maps"), ids_map389 SEC(".maps"), \
ids_map390 SEC(".maps"), ids_map391 SEC(".maps"), ids_map392 SEC(".maps"), \
ids_map393 SEC(".maps"), ids_map394 SEC(".maps"), ids_map395 SEC(".maps"), \
ids_map396 SEC(".maps"), ids_map397 SEC(".maps"), ids_map398 SEC(".maps"), \
ids_map399 SEC(".maps"), ids_map400 SEC(".maps"), ids_map401 SEC(".maps"), \
ids_map402 SEC(".maps"), ids_map403 SEC(".maps"), ids_map404 SEC(".maps"), \
ids_map405 SEC(".maps"), ids_map406 SEC(".maps"), ids_map407 SEC(".maps"), \
ids_map408 SEC(".maps"), ids_map409 SEC(".maps"), ids_map410 SEC(".maps"), \
ids_map411 SEC(".maps"), ids_map412 SEC(".maps"), ids_map413 SEC(".maps"), \
ids_map414 SEC(".maps"), ids_map415 SEC(".maps"), ids_map416 SEC(".maps"), \
ids_map417 SEC(".maps"), ids_map418 SEC(".maps"), ids_map419 SEC(".maps"), \
ids_map420 SEC(".maps"), ids_map421 SEC(".maps"), ids_map422 SEC(".maps"), \
ids_map423 SEC(".maps"), ids_map424 SEC(".maps"), ids_map425 SEC(".maps"), \
ids_map426 SEC(".maps"), ids_map427 SEC(".maps"), ids_map428 SEC(".maps"), \
ids_map429 SEC(".maps"), ids_map430 SEC(".maps"), ids_map431 SEC(".maps"), \
ids_map432 SEC(".maps"), ids_map433 SEC(".maps"), ids_map434 SEC(".maps"), \
ids_map435 SEC(".maps"), ids_map436 SEC(".maps"), ids_map437 SEC(".maps"), \
ids_map438 SEC(".maps"), ids_map439 SEC(".maps"), ids_map440 SEC(".maps"), \
ids_map441 SEC(".maps"), ids_map442 SEC(".maps"), ids_map443 SEC(".maps"), \
ids_map444 SEC(".maps"), ids_map445 SEC(".maps"), ids_map446 SEC(".maps"), \
ids_map447 SEC(".maps"), ids_map448 SEC(".maps"), ids_map449 SEC(".maps"), \
ids_map450 SEC(".maps"), ids_map451 SEC(".maps"), ids_map452 SEC(".maps"), \
ids_map453 SEC(".maps"), ids_map454 SEC(".maps"), ids_map455 SEC(".maps"), \
ids_map456 SEC(".maps"), ids_map457 SEC(".maps"), ids_map458 SEC(".maps"), \
ids_map459 SEC(".maps"), ids_map460 SEC(".maps"), ids_map461 SEC(".maps"), \
ids_map462 SEC(".maps"), ids_map463 SEC(".maps"), ids_map464 SEC(".maps"), \
ids_map465 SEC(".maps"), ids_map466 SEC(".maps"), ids_map467 SEC(".maps"), \
ids_map468 SEC(".maps"), ids_map469 SEC(".maps"), ids_map470 SEC(".maps"), \
ids_map471 SEC(".maps"), ids_map472 SEC(".maps"), ids_map473 SEC(".maps"), \
ids_map474 SEC(".maps"), ids_map475 SEC(".maps"), ids_map476 SEC(".maps"), \
ids_map477 SEC(".maps"), ids_map478 SEC(".maps"), ids_map479 SEC(".maps"), \
ids_map480 SEC(".maps"), ids_map481 SEC(".maps"), ids_map482 SEC(".maps"), \
ids_map483 SEC(".maps"), ids_map484 SEC(".maps"), ids_map485 SEC(".maps"), \
ids_map486 SEC(".maps"), ids_map487 SEC(".maps"), ids_map488 SEC(".maps"), \
ids_map489 SEC(".maps"), ids_map490 SEC(".maps"), ids_map491 SEC(".maps"), \
ids_map492 SEC(".maps"), ids_map493 SEC(".maps"), ids_map494 SEC(".maps"), \
ids_map495 SEC(".maps"), ids_map496 SEC(".maps"), ids_map497 SEC(".maps"), \
ids_map498 SEC(".maps"), ids_map499 SEC(".maps"), ids_map500 SEC(".maps"), \
ids_map501 SEC(".maps"), ids_map502 SEC(".maps"), ids_map503 SEC(".maps"), \
ids_map504 SEC(".maps"), ids_map505 SEC(".maps");
*/


struct global_map_t {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, __u32);
    __uint(max_entries, 1500);
    __array(values, struct ids_map);
} global_map SEC(".maps") = {
    .values = {
        &ids_map0, &ids_map1, &ids_map2, &ids_map3, &ids_map4, &ids_map5, \
        &ids_map6, &ids_map7, &ids_map8, &ids_map9, &ids_map10, &ids_map11, \
        &ids_map12, &ids_map13, &ids_map14, &ids_map15, &ids_map16, &ids_map17, \
        &ids_map18, &ids_map19, &ids_map20, &ids_map21, &ids_map22, &ids_map23, \
        &ids_map24, &ids_map25, &ids_map26, &ids_map27, &ids_map28, &ids_map29, \
        &ids_map30, &ids_map31, &ids_map32, &ids_map33, &ids_map34, &ids_map35, \
        &ids_map36, &ids_map37, &ids_map38, &ids_map39, &ids_map40, &ids_map41, \
        &ids_map42, &ids_map43, &ids_map44, &ids_map45, &ids_map46, &ids_map47, \
        &ids_map48, &ids_map49, &ids_map50, &ids_map51, &ids_map52, &ids_map53, \
        &ids_map54, &ids_map55, &ids_map56, &ids_map57, &ids_map58, &ids_map59, \
        &ids_map60, &ids_map61, &ids_map62, &ids_map63, &ids_map64, &ids_map65, \
        &ids_map66, &ids_map67, &ids_map68, &ids_map69, &ids_map70, &ids_map71, \
        &ids_map72, &ids_map73, &ids_map74, &ids_map75, &ids_map76, &ids_map77, \
        &ids_map78, &ids_map79, &ids_map80, &ids_map81, &ids_map82, &ids_map83, \
        &ids_map84, &ids_map85, &ids_map86, &ids_map87, &ids_map88, &ids_map89, \
        &ids_map90, &ids_map91, &ids_map92, &ids_map93, &ids_map94, &ids_map95, \
        &ids_map96, &ids_map97, &ids_map98, &ids_map99, &ids_map100, &ids_map101, \
        &ids_map102, &ids_map103, &ids_map104, &ids_map105, &ids_map106, &ids_map107, \
        &ids_map108, &ids_map109, &ids_map110, &ids_map111, &ids_map112, &ids_map113, \
        &ids_map114, &ids_map115, &ids_map116, &ids_map117, &ids_map118, &ids_map119, \
        &ids_map120, &ids_map121, &ids_map122, &ids_map123, &ids_map124, &ids_map125, \
        &ids_map126, &ids_map127, &ids_map128, &ids_map129, &ids_map130, &ids_map131, \
        &ids_map132, &ids_map133, &ids_map134, &ids_map135, &ids_map136, &ids_map137, \
        &ids_map138, &ids_map139, &ids_map140, &ids_map141, &ids_map142, &ids_map143, \
        &ids_map144, &ids_map145, &ids_map146, &ids_map147, &ids_map148, &ids_map149, \
        &ids_map150, &ids_map151, &ids_map152, &ids_map153, &ids_map154, &ids_map155, \
        &ids_map156, &ids_map157, &ids_map158, &ids_map159, &ids_map160, &ids_map161, \
        &ids_map162, &ids_map163, &ids_map164, &ids_map165, &ids_map166, &ids_map167, \
        &ids_map168, &ids_map169, &ids_map170, &ids_map171, &ids_map172, &ids_map173, \
        &ids_map174, &ids_map175, &ids_map176, &ids_map177, &ids_map178, &ids_map179, \
        &ids_map180, &ids_map181, &ids_map182, &ids_map183, &ids_map184, &ids_map185, \
        &ids_map186, &ids_map187, &ids_map188, &ids_map189, &ids_map190, &ids_map191, \
        &ids_map192, &ids_map193, &ids_map194, &ids_map195, &ids_map196, &ids_map197, \
        &ids_map198, &ids_map199, &ids_map200, &ids_map201, &ids_map202, &ids_map203, \
        &ids_map204, &ids_map205, &ids_map206, &ids_map207, &ids_map208, &ids_map209, \
        &ids_map210, &ids_map211, &ids_map212, &ids_map213, &ids_map214, &ids_map215, \
        &ids_map216, &ids_map217, &ids_map218, &ids_map219, &ids_map220, &ids_map221, \
        &ids_map222, &ids_map223, &ids_map224, &ids_map225, &ids_map226, &ids_map227, \
        &ids_map228, &ids_map229, &ids_map230, &ids_map231, &ids_map232, &ids_map233, \
        &ids_map234, &ids_map235, &ids_map236, &ids_map237, &ids_map238, &ids_map239, \
        &ids_map240, &ids_map241, &ids_map242, &ids_map243, &ids_map244, &ids_map245, \
        &ids_map246, &ids_map247, &ids_map248, &ids_map249, &ids_map250, &ids_map251, \
        &ids_map252, &ids_map253, &ids_map254}
};
        /*
        , &ids_map255, &ids_map256}};
        &ids_map257, \
        &ids_map258, &ids_map259, &ids_map260, &ids_map261, &ids_map262, &ids_map263, \
        &ids_map264, &ids_map265, &ids_map266, &ids_map267, &ids_map268, &ids_map269, \
        &ids_map270, &ids_map271, &ids_map272, &ids_map273, &ids_map274, &ids_map275, \
        &ids_map276, &ids_map277, &ids_map278, &ids_map279, &ids_map280, &ids_map281, \
        &ids_map282, &ids_map283, &ids_map284, &ids_map285, &ids_map286, &ids_map287, \
        &ids_map288, &ids_map289, &ids_map290, &ids_map291, &ids_map292, &ids_map293, \
        &ids_map294, &ids_map295, &ids_map296, &ids_map297, &ids_map298, &ids_map299, \
        &ids_map300, &ids_map301, &ids_map302, &ids_map303, &ids_map304, &ids_map305, \
        &ids_map306, &ids_map307, &ids_map308, &ids_map309, &ids_map310, &ids_map311, \
        &ids_map312, &ids_map313, &ids_map314, &ids_map315, &ids_map316, &ids_map317, \
        &ids_map318, &ids_map319, &ids_map320, &ids_map321, &ids_map322, &ids_map323, \
        &ids_map324, &ids_map325, &ids_map326, &ids_map327, &ids_map328, &ids_map329, \
        &ids_map330, &ids_map331, &ids_map332, &ids_map333, &ids_map334, &ids_map335, \
        &ids_map336, &ids_map337, &ids_map338, &ids_map339, &ids_map340, &ids_map341, \
        &ids_map342, &ids_map343, &ids_map344, &ids_map345, &ids_map346, &ids_map347, \
        &ids_map348, &ids_map349, &ids_map350, &ids_map351, &ids_map352, &ids_map353, \
        &ids_map354, &ids_map355, &ids_map356, &ids_map357, &ids_map358, &ids_map359, \
        &ids_map360, &ids_map361, &ids_map362, &ids_map363, &ids_map364, &ids_map365, \
        &ids_map366, &ids_map367, &ids_map368, &ids_map369, &ids_map370, &ids_map371, \
        &ids_map372, &ids_map373, &ids_map374, &ids_map375, &ids_map376, &ids_map377, \
        &ids_map378, &ids_map379, &ids_map380, &ids_map381, &ids_map382, &ids_map383, \
        &ids_map384, &ids_map385, &ids_map386, &ids_map387, &ids_map388, &ids_map389, \
        &ids_map390, &ids_map391, &ids_map392, &ids_map393, &ids_map394, &ids_map395, \
        &ids_map396, &ids_map397, &ids_map398, &ids_map399, &ids_map400, &ids_map401, \
        &ids_map402, &ids_map403, &ids_map404, &ids_map405, &ids_map406, &ids_map407, \
        &ids_map408, &ids_map409, &ids_map410, &ids_map411, &ids_map412, &ids_map413, \
        &ids_map414, &ids_map415, &ids_map416, &ids_map417, &ids_map418, &ids_map419, \
        &ids_map420, &ids_map421, &ids_map422, &ids_map423, &ids_map424, &ids_map425, \
        &ids_map426, &ids_map427, &ids_map428, &ids_map429, &ids_map430, &ids_map431, \
        &ids_map432, &ids_map433, &ids_map434, &ids_map435, &ids_map436, &ids_map437, \
        &ids_map438, &ids_map439, &ids_map440, &ids_map441, &ids_map442, &ids_map443, \
        &ids_map444, &ids_map445, &ids_map446, &ids_map447, &ids_map448, &ids_map449, \
        &ids_map450, &ids_map451, &ids_map452, &ids_map453, &ids_map454, &ids_map455, \
        &ids_map456, &ids_map457, &ids_map458, &ids_map459, &ids_map460, &ids_map461, \
        &ids_map462, &ids_map463, &ids_map464, &ids_map465, &ids_map466, &ids_map467, \
        &ids_map468, &ids_map469, &ids_map470, &ids_map471, &ids_map472, &ids_map473, \
        &ids_map474, &ids_map475, &ids_map476, &ids_map477, &ids_map478, &ids_map479, \
        &ids_map480, &ids_map481, &ids_map482, &ids_map483, &ids_map484, &ids_map485, \
        &ids_map486, &ids_map487, &ids_map488, &ids_map489, &ids_map490, &ids_map491, \
        &ids_map492, &ids_map493, &ids_map494, &ids_map495, &ids_map496, &ids_map497, \
        &ids_map498, &ids_map499, &ids_map500, &ids_map501, &ids_map502, &ids_map503, \
        &ids_map504, &ids_map505 }
    };
*/

struct port_map_t {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PORT_RANGE);
    __type(key, struct port_map_key);
    __type(value, __u32);
} tcp_port_map SEC(".maps"), udp_port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, TAIL_CALL_MAP_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} tail_call_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} counter_map SEC(".maps");

// os 4 primeiros campos foram registrados em seções BTF. Os últimos 3 são somente para tail call
struct xdp_hints_mark {
        __u32 mark;
        __u32 global_map_index;
        __u32 rule_index;
        __u32 btf_id;
} __attribute__((aligned(4))) __attribute__((packed));

#endif

