/* Test type containment and equivalence relations. */

#include <cstdio>
#include <iostream>
#include <map>

#include <boost/graph/graph_traits.hpp>
#include <processimage/process.hpp>
/*namespace boost {
	template <> struct graph_traits< process_image::my_master_type_containment_t >;
}
*/
#include <boost/graph/graph_concepts.hpp>

#include <boost/graph/transitive_closure.hpp>

/* 0. Check concepts for graph type. */
typedef process_image::my_master_type_containment_t Graph;

/* 1. Load in a program whose debug info describes some type containment. */
process_image me(-1);

inline void print_opt_ident_path(std::ostream& s, const std::vector<boost::optional<std::string> >& arg)
{
	for (auto i_name = arg.begin();
			i_name != arg.end();
			i_name++)
	{
		if (i_name != arg.begin()) s << "::";
		s << ((*i_name) ? **i_name : "(anon)");
	}
}

int main(void)
{
	/* 1.5. Check concepts for graph type. */
    boost::function_requires< boost::AdjacencyGraphConcept<Graph> >();
    boost::function_requires< boost::AdjacencyMatrixConcept<Graph> >();
    boost::function_requires< boost::VertexListGraphConcept<Graph> >();    

	/* 2. Dump the relations -- equivalence and containment. */
	for (auto i_class = me.get_master_type_equivalence().begin();
			i_class != me.get_master_type_equivalence().end();
			i_class++)
	{
		std::cout << "Equivalence class ";
		print_opt_ident_path(std::cout, i_class->first);
		std::cout << " contains types: ";
		for (auto i_pos = i_class->second.begin();
				i_pos != i_class->second.end();
				i_pos++)
		{
			if (i_pos != i_class->second.begin()) std::cout << ", ";
			print_opt_ident_path(std::cout, (*i_pos->p_ds)[i_pos->off]->opt_ident_path_from_root());
		}
		std::cout << std::endl;
	}

	/* 3. Run some graph algorithms on the containment relation. */

/* Here's what I did for topological sort. */
/*    std::map<
    	boost::graph_traits<cpp_dependency_order>::vertex_descriptor, 
    	boost::default_color_type
    > underlying_topsort_node_color_map;
     auto topsort_color_map = boost::make_assoc_property_map( // ColorMap provides a mutable "Color" property per node
   	    underlying_topsort_node_color_map
       );
    auto named_params = boost::color_map(topsort_color_map);
    boost::topological_sort(*this, std::back_inserter(topsorted_container), named_params);
*/

	Graph out(me);
	
	/*
		UTIL/OUT: orig_to_copy(G_to_TC_VertexMap g_to_tc_map)
		
		This maps each vertex in the input graph to the new matching vertices in the output
transitive closure graph.

		Python: This must be a vertex_vertex_map of the graph.
		
		IN: vertex_index_map(VertexIndexMap& index_map)
		
		This maps each vertex to an integer in the range [0, num_vertices(g)). This parameter is
only necessary when the default color property map is used. The type VertexIndexMap must be a model
of Readable Property Map. The value type of the map must be an integer type. The vertex descriptor
type of the graph needs to be usable as the key type of the map.

		Default: get(vertex_index, g) Note: if you use this default, make sure your graph has an
internal vertex_index property. For example, adjacenty_list with VertexList=listS does not have an
internal vertex_index property. 

		Python: Unsupported parameter.	
	*/
	
	std::map<
            boost::graph_traits<Graph>::vertex_descriptor, 
            boost::default_color_type
        > underlying_node_color_map;
	auto color_map = boost::make_assoc_property_map( // ColorMap provides a mutable "Color" property per node
                    underlying_node_color_map
            );
	auto named_params = boost::color_map(color_map);
	boost::transitive_closure(me.get_master_type_containment(), out, named_params);
	

}
