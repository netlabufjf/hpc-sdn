# Modulo de calculo de caminhos mais curtos - Versao 2.0
# Numero de caminhos: entre switches de acesso do mesmo POD - m/2; entre switches de acesso de PODs diferentes - (m/2)^^2

# Funcao de entrada do modulo que implementa o algoritmo de Dijkstra baseado no pseudo-codigo do Prof. Jairo Souza
# Recebe a lista de adjacencias e, para cada origem, cria uma lista de predecessores e chama a funcao 'percurso'
# Formato da lista de adjacencias: {sw_src_1:{sw_dst_1:custo,sw_dst_2:custo,...},sw_src_2:{sw_dst_1:custo,sw_dst_2:custo,...},...}
# Retorna uma lista (paths) com todos os caminhos mais curtos a partir de todas as origens
def dijkstra(adj_list):

	global tree

	paths = []
	tree = []

	for src in range(1,len(adj_list)+1):

		curdist = {}
		predecessor = {}

		# Para todo vertice V faz CURDIST = 1000
		vertices = [v for v in adj_list.keys()]
		for v in vertices:
			curdist[v] = 1000
			predecessor[v] = []

		# CURDIST(SRC) = 0
		curdist[src] = 0

		# TOBECHECKED = VERTICES
		tobechecked = [v for v in vertices]

		# Enquanto TOBECHECKED nao vazio
		while tobechecked:

			# Descobre vertice V com menor valor de CURDIST
			v = tobechecked[0]
			min_curdist = curdist[v]
			for i in curdist.keys():
				if (i in tobechecked) and curdist[i] < min_curdist:
					min_curdist = curdist[i]
					v = i

			# Remove V de TOBECHECKED
			tobechecked.remove(v)
		
			# Para todo U adjacente a V tal que U pertence a TOBECHECKED
			adj = adj_list[v].keys()
			for u in adj:
				if u in tobechecked:
					if curdist[u] >= (curdist[v] + adj_list[v][u]):
						curdist[u] = curdist[v] + adj_list[v][u]
						predecessor[u].append(v)

		# Gera os caminhos a partir dos predecessores
		for dst in range(1,len(adj_list)+1):
			percurso(predecessor,dst,src,dst)
			aux = []
			for t in tree:
			        aux.append(t)
			        if t == src:
	        		        aux.reverse()
					if dst not in aux:
	        	        		aux.append(dst)
		                	paths.append(aux)
	                		aux = []
			if tree == []:
			        paths.append([src])
			tree = []
				
	return paths

# Funcao recursiva complementar que gera uma lista (tree) com todos os caminhos entre os predecessores do destino (dst) e a origem (src)
# Exemplo: src - 13; dst - 15; tree - [7,1,5,13,7,2,5,13,8,3,6,13,8,4,6,13]
def percurso(predecessor,i,src,dst):
        for a in predecessor[i]:
                if a == src:
                        tree.append(i)
                        tree.append(a)
                else:
                        if i != dst:
                                tree.append(i)
                        percurso(predecessor,a,src,dst)
