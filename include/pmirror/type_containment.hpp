class type_containment
{
/* This stuff is cut out of process_image definition in process.hpp */
public:
	typedef std::vector< boost::optional<std::string> > type_equivalence_class;
	typedef std::map<
		type_equivalence_class,
		std::set< dwarf::spec::abstract_dieset::position >
		> master_type_equivalence_t;
private:
	master_type_equivalence_t master_type_equivalence;
public:
	const master_type_equivalence_t& get_master_type_equivalence() const
	{ return master_type_equivalence; }
	master_type_equivalence_t& get_master_type_equivalence()
	{ return master_type_equivalence; }
	
	/* I thought about making master type containment  a *set of pairs*, 
	 * not a multimap (which is effectively a multiset of pairs). 
	 * This would mean we have to write our own find() and operator[],
	 * in effect, but don't have to be careful about checking
	 * for uniqueness of entries.
	 * Decided AGAINST this because uniqueness checking happens only on
	 * update(), i.e. a slow-path operation,
	 * whereas we want to be able to do a lookup for a given contained type *fast*. */
public:
	typedef std::/*set*/multimap< /*std::pair<*/type_equivalence_class, 
					type_equivalence_class/*>*/ >  master_type_containment_t;
	struct my_master_type_containment_t : public master_type_containment_t
	{
		process_image *containing_image;
		my_master_type_containment_t(process_image& i) 
		: master_type_containment_t(), containing_image(&i) {}
	};
private:
	my_master_type_containment_t master_type_containment;
public:
	const my_master_type_containment_t& get_master_type_containment() const
	{ return master_type_containment; }
	my_master_type_containment_t& get_master_type_containment()
	{ return master_type_containment; }

private:
	void update_master_type_containment();
	void update_master_type_equivalence();
	
	virtual bool type_equivalence(boost::shared_ptr<dwarf::spec::type_die> t1,
		boost::shared_ptr<dwarf::spec::type_die> t2);
	
	void write_type_containment_relation(
		std::multimap<lib::Dwarf_Off, lib::Dwarf_Off>& out_mm,
		spec::abstract_dieset& ds); 
};

// this is from process.hpp too

namespace boost {
template <>
struct graph_traits<process_image::my_master_type_containment_t>
{
	typedef process_image::type_equivalence_class vertex_descriptor;
	typedef process_image::my_master_type_containment_t::value_type edge_descriptor;

	// edge iterators are just iterators within the map
	typedef process_image::my_master_type_containment_t::iterator out_edge_iterator;

	/* vertex iterators are iterators through the set of 
	 * type equivalence classes in the map */
	typedef process_image::master_type_equivalence_t::iterator vertex_iterator;
	
	typedef process_image::master_type_equivalence_t::size_type vertices_size_type;
	typedef process_image::master_type_equivalence_t::size_type degree_size_type;

	// we are directed, and parallel edges are *not* allowed
	// (although one type may contain another in multiple locations...
	// ... but we capture this out-of-band)
	typedef directed_tag directed_category;
	typedef disallow_parallel_edge_tag edge_parallel_category;

	// we are both a vertex list graph and an incidence graph
    struct traversal_tag :
      public virtual vertex_list_graph_tag,
      public virtual incidence_graph_tag,
	  public virtual adjacency_graph_tag,
	  public virtual adjacency_matrix_tag { };
    typedef traversal_tag traversal_category;
	
	/* We are also an adjacency graph. This means that one can get an iterator
	 * for any vertex, that iterates through the vertices that can be reached
	 * from it in a single hop. We implement this just like out_edges. */
	typedef out_edge_iterator adjacency_iterator;
	
};

// template<> struct property_traits<process_image::my_master_type_containment_t>
// {
// 	/* vertex_property_type */
// 	typedef boost::no_property vertex_property_type;
// 
// };
} // end namespace boost

inline graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor
source(
    graph_traits<process_image::my_master_type_containment_t>::edge_descriptor e,
    const process_image::my_master_type_containment_t& g)
{
	return e.first;
}

inline graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor
target(
    graph_traits<process_image::my_master_type_containment_t>::edge_descriptor e,
    const process_image::my_master_type_containment_t& g)
{
	return e.second;
}

inline std::pair<
    graph_traits<process_image::my_master_type_containment_t>::out_edge_iterator,
    graph_traits<process_image::my_master_type_containment_t>::out_edge_iterator >  
out_edges(
    graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor u, 
    const process_image::my_master_type_containment_t& g)
{
	return const_cast<process_image::my_master_type_containment_t&>(g).equal_range(u);
}

inline graph_traits<process_image::my_master_type_containment_t>::degree_size_type
out_degree(
	graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor u,
	const process_image::my_master_type_containment_t& g)
{
	return srk31::count(
		const_cast<process_image::my_master_type_containment_t&>(g).equal_range(u).first, 
		const_cast<process_image::my_master_type_containment_t&>(g).equal_range(u).second);
}

inline std::pair<
    graph_traits<process_image::my_master_type_containment_t>::out_edge_iterator,
    graph_traits<process_image::my_master_type_containment_t>::out_edge_iterator >  
adjacent_vertices(graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor u, 
    const process_image::my_master_type_containment_t& g)
{
	return const_cast<process_image::my_master_type_containment_t&>(g).equal_range(u);
}

inline std::pair<
	graph_traits<process_image::my_master_type_containment_t>::vertex_iterator,
	graph_traits<process_image::my_master_type_containment_t>::vertex_iterator >
vertices(const process_image::my_master_type_containment_t& g)
{
	// the tricky one: we need to get the associated equivalence map
	return std::make_pair(
		g.containing_image->get_master_type_equivalence().begin(),
		g.containing_image->get_master_type_equivalence().end());
}

inline graph_traits<process_image::my_master_type_containment_t>::vertices_size_type
num_vertices(const process_image::my_master_type_containment_t& g)
{
	return g.containing_image->get_master_type_equivalence().size();
}

inline graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor
add_vertex(process_image::my_master_type_containment_t& g)
{
	throw "blah";
}

inline void
remove_vertex(graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor u,
	process_image::my_master_type_containment_t& g)
{
	g.containing_image->get_master_type_equivalence().erase(u);
}

inline std::pair<
	graph_traits<process_image::my_master_type_containment_t>::edge_descriptor, bool>
add_edge(
	graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor u,
	graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor v, 
	process_image::my_master_type_containment_t& g)
{
	/* Insert -- we avoid inserting duplicates because
	 * it's a multimap and we want a multi-key unique-value map. */
	process_image::my_master_type_containment_t::value_type entry = std::make_pair(u, v);
	auto iter = std::find(
		g.begin(), 
		g.end(), 
		entry);
	if (iter == g.end())
	{
		g.insert(entry);
		return std::make_pair(entry, true);
	}
	else return std::make_pair(*iter, false);
}

/*

Semantics: Try to insert the edge (u,v) into the graph, returning the inserted edge or a parallel
edge and a flag that specifies whether an edge was inserted. This operation must not invalidate
vertex descriptors or vertex iterators of the graph, though it may invalidate edge descriptors or
edge iterators.

Preconditions: u and v are vertices in the graph. 

Postconditions: (u,v) is in the edge set of the graph. The returned edge descriptor will have u in
the source position and v in the target position. If the graph allows parallel edges, then the
returned flag is always true. If the graph does not allow parallel edges, if (u,v) was already in
the graph then the returned flag is false. If (u,v) was not in the graph then the returned flag is
true.

*/ 

inline void
remove_edge(
	graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor u,
	graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor v, 
	process_image::my_master_type_containment_t& g)
{
	process_image::my_master_type_containment_t::value_type entry = std::make_pair(u, v);
	auto iter = std::find(
		g.begin(), 
		g.end(), 
		entry);
	if (iter == g.end()) return;
	else g.erase(iter);
}
/*

Semantics: Remove the edge (u,v) from the graph. If the graph allows parallel edges this removes
all occurrences of (u,v). 

Precondition: (u,v) is in the edge set of the graph. 

Postcondition: (u,v) is no longer in the edge set of the graph. 

*/

inline void 
remove_edge(
	graph_traits<process_image::my_master_type_containment_t>::edge_descriptor e,
	process_image::my_master_type_containment_t& g)
{
	auto iter = std::find(
		g.begin(), 
		g.end(), 
		e);
	if (iter != g.end()) g.erase(iter);
}

/*

Semantics: Remove the edge e from the graph.

Precondition: e is an edge in the graph. 

Postcondition: e is no longer in the edge set for g. 
*/

inline void 
clear_vertex(
	graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor u, 
	process_image::my_master_type_containment_t& g)
{
	auto edges_pair = out_edges(u, g);
	for (auto i_edge = edges_pair.first; i_edge != edges_pair.second; i_edge++)
	{
		remove_edge(*i_edge, g);
	}
}	

/*

Semantics: Remove all edges to and from vertex u from the graph. 

Precondition: u is a valid vertex descriptor of g. 

Postconditions: u does not appear as a source or target of any edge in g.
*/
//} // end namespace boost

