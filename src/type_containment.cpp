void 
process_image::update_master_type_equivalence()
{
	/* DEBUG: this seems to be very expensive. It shouldn't be any more expensive
	 * than dwarfdumping the whole library. That might still be too much though! 
	 * Recall: why are we doing this?
	 * - 1. to canonicalise object types, for Cake runtime type lookup? 
	 * - 2. to do heap object .
	 *
	 * We can make this faster by:
	 * 1. don't blithely DFS; write a custom search which only descends when
	 *    appropriate.
	 * 2. */
	static int called_count = 0;
	std::cerr << "Called update_master_type_equivalence for the " 
		<< ++called_count << srk31::ordinal_suffix(called_count) << " time." << std::endl; 

	/* For each type, 
	 * - add it to the set under its key 
	 * - check that it is rep-compatible with...
	 *   ... *NOT* every other type in there, but
	     ... the *first* type in there only! Rely on transitivity! */
	 
	for (auto i_file = files.begin(); i_file != files.end(); i_file++)
	{
		if (!i_file->second.p_ds) continue;
		for (auto i_die = i_file->second.p_ds->begin();
				i_die != i_file->second.p_ds->end();
				i_die++)
		{
			auto t = boost::dynamic_pointer_cast<dwarf::spec::type_die>(*i_die);
			if (t)
			{
				auto key = t->opt_ident_path_from_cu();
				
				// check rep-compatibility with every other element
				auto i_pos_plus_one = master_type_equivalence[key].begin();
				if  (master_type_equivalence[key].begin() != master_type_equivalence[key].end())
				{ i_pos_plus_one++; }

				for (auto i_pos = master_type_equivalence[key].begin();
						i_pos !=  /*master_type_equivalence[key].end();*/ i_pos_plus_one;
						i_pos++)
				{
					auto t_test = boost::dynamic_pointer_cast<dwarf::spec::type_die>(
						(*i_pos->p_ds)[i_pos->off]);
					assert(t_test && t->is_rep_compatible(t_test) && 
						t_test->is_rep_compatible(t));
					// FIXME: This assertion might fail for like-named toplevel types.
					// Fix by adding a 'hash' of the type's rep/layout to the key
					// (need not be a well-behaved hash function, just likely-unique).
				}
			
				master_type_equivalence[
					t->opt_ident_path_from_cu()
				].insert(
					(dwarf::spec::abstract_dieset::position) { 
						i_file->second.p_ds.get(),
						t->get_offset()
					});
			}
		}
	}
	std::cerr << "Finished the " << called_count << srk31::ordinal_suffix(called_count)
	<< "call to update_master_type_equivalence()." << std::endl; 
}

void
process_image::update_master_type_containment()
{
	// ASSERT: that this is called immediately after update_master_type_equivalence()!

	/* Assume a precomputed set of type equivalence pairs. 
	 *
	 * For each dieset's type containment relation, 
	 * we add edges to the master relation
	 * for the contained type (first element in pair)
	 * and all equivalent types in other diesets.
	 *
	 * Q: do we also want to normalise the second element
	 * to something denoting its whole equivalence class? 
	 * A: Yes. */
	
	for (auto i_file = files.begin(); i_file != files.end(); i_file++)
	{
		for (auto i_entry = i_file->second.ds_type_containment.begin();
				i_entry != i_file->second.ds_type_containment.end();
				i_entry++)
		{
			// each entry is a pair <off1, off2>
			// where the type at off2 _immediately contains_ that at off1
			master_type_containment_t::value_type entry = std::make_pair(
				 (*i_file->second.p_ds)[i_entry->first]->opt_ident_path_from_cu(),
				 (*i_file->second.p_ds)[i_entry->second]->opt_ident_path_from_cu()
				 );
			
			/* Insert -- we avoid inserting duplicates because
			 * it's a multimap and we want a multi-key unique-value map. */
			if (std::find(master_type_containment.begin(), master_type_containment.end(), entry)
				 == master_type_containment.end())
			{
				master_type_containment.insert(entry);
			}
		}
	}
}

bool
process_image::type_equivalence(boost::shared_ptr<dwarf::spec::type_die> t1,
		boost::shared_ptr<dwarf::spec::type_die> t2)
{
	return t1->opt_ident_path_from_cu() == t2->opt_ident_path_from_cu()
		&& t1->is_rep_compatible(t2) && t2->is_rep_compatible(t1);
}
boost::shared_ptr<dwarf::spec::basic_die> 
process_image::discover_heap_object(addr_t heap_loc,
    boost::shared_ptr<dwarf::spec::type_die> imprecise_static_type,
    addr_t *out_object_start_addr)
{
    static bool warned = false;
	using boost::shared_ptr;
	using dwarf::lib::Dwarf_Unsigned;
	using dwarf::lib::Dwarf_Off;
    
    assert (alloc_list_head_ptr_addr != 0);

    void *alloc_list_head_addr = *unw_read_ptr<void*>(
        unw_as, unw_priv, reinterpret_cast<void**>(alloc_list_head_ptr_addr));
    // if my template class works, we should just be able to walk the list...
	unw_read_ptr<alloc> n(unw_as, 
        			unw_priv,
        			reinterpret_cast<alloc*>(alloc_list_head_addr));
    std::cerr << "Remote read head alloc is at " << alloc_list_head_addr 
        << " and has begin " << n->begin
        << ", size " << static_cast<unsigned>(n->size) /* avoid size_t printing in hex */
        << " bytes, next " << n->next
        << std::endl;    
	
	// FIXME: if n has precise static type info in it,
	// just retrieve it and we're done.
	
	for (;
            	n != 0;
                n = n->next)
    {
        off_t offset_into_block = reinterpret_cast<char*>(heap_loc) 
            - reinterpret_cast<char*>(n->begin);
        // candidates are containing types which satisfy our offset constraints
        std::vector<shared_ptr<spec::type_die> > candidates;
    	if (heap_loc >= reinterpret_cast<addr_t>(n->begin) 
			&& offset_into_block < n->size)
        {
        	std::cerr << "Detected that heap location 0x" << std::hex << heap_loc
            	<< " is part of region beginning 0x" << std::hex << n->begin
                << " with size " << n->size << " bytes." << std::endl;

            /* Now we do what's described in the Cake paper. 
             * 
             * First, consider block-scale adjustments. 
             * In this, the pointer is
             * - to a block whose size is a multiple of the expected size;
             * - into the block at an integer multiple of the element size. */

            auto type = imprecise_static_type;
            boost::optional<Dwarf_Unsigned> opt_byte_size = 
                type->calculate_byte_size();
            assert (opt_byte_size);
            Dwarf_Unsigned byte_size = *opt_byte_size;
            //	= dwarf::abstract::Die_abstract_is_type<dwarf::encap::die>
            //    	::calculate_byte_size(*type);
            if (n->size % byte_size == 0
                && offset_into_block % byte_size == 0)
            {
                std::cerr << "Detected array of " 
                    // workaround size_t hex printing annoyance
                    << static_cast<unsigned long>(n->size / byte_size)
                    << " elements of type " << 
						(imprecise_static_type->get_name() ? *imprecise_static_type->get_name() : "(anon)" )
                    << " (size " << static_cast<unsigned long>(n->size) << ")"
                    << std::endl;
            } // end if block-scale
            else
            {
                /* The tricky one: byte-scale adjustment.
                 * Find all the admissible containing types
                 * whose byte-size matches the block size. */
				
				/* Q: For DwarfPython, what are we going to do when we
				 * have no imprecise static type? 
				 * A: Make sure DwarfPython-allocated objects store
				 * precise static type info at allocation time, or
				 * (for strings that are embedded in the AST) some
				 * time before we try to do the discovery thing on them. */
				assert(imprecise_static_type);
				std::vector<boost::shared_ptr<dwarf::spec::type_die> > candidates;

				/* We need the reachability in the master containment
				 * relation, because we want to handle indirect containment.
				 * So we want to find all the types reachable from the
				 * (reflexive) containment relation. We have the non-reflexive
				 * relation, so we just add back in the starting node. */
                auto containing_types = 
					master_type_containment.equal_range(
						imprecise_static_type->get_concrete_type()->opt_ident_path_from_cu()
					);
				for (auto i_containment_pair = containing_types.first;
						i_containment_pair != containing_types.second;
						i_containment_pair++)
				{
					// FIXME: use reachability here!
					assert(master_type_equivalence[i_containment_pair->second].begin()
						!= master_type_equivalence[i_containment_pair->second].end());
						
					auto containing_type_position = // look up an arbitrary element of the equiv. class
						*master_type_equivalence[i_containment_pair->second].begin();
					
					auto containing_type = boost::dynamic_pointer_cast<dwarf::spec::type_die>(
						(*containing_type_position.p_ds)[containing_type_position.off]);
					assert(containing_type);
					
					// Now for each position at which this type contains our imprecise type
					for (auto i_child = containing_type->children_begin();
							i_child != containing_type->children_end();
							i_child++)
					{
                    	if ((*i_child)->get_tag() == DW_TAG_member
                        	|| (*i_child)->get_tag() == DW_TAG_inheritance)
                    	{
							// skip occurrences where this doesn't have the type we're interested in
							auto child_describing_layout
							 = boost::dynamic_pointer_cast<dwarf::spec::with_type_describing_layout_die>(
							 	*i_child);
							if (!child_describing_layout
							 || !child_describing_layout->get_type()
							 || !(*child_describing_layout->get_type())->get_concrete_type()
							 || (*child_describing_layout->get_type())->get_concrete_type()->
							 	opt_ident_path_from_cu()
							 	!= imprecise_static_type->get_concrete_type()->opt_ident_path_from_cu()) 
								continue;
							// FIXME: use more abstract test here
							// (Define a function that gets the equivalence class identifier
						
                        	assert(containing_type->calculate_byte_size());
							
							

                        	if (*containing_type->calculate_byte_size() == n->size)
                        	{
                            	// check the offset as well
                            	switch((*i_child)->get_tag())
                            	{
                                	case DW_TAG_member: {
                                    	auto member = boost::dynamic_pointer_cast<spec::member_die>(
                                        		*i_child);
							        	Dwarf_Off containing_offset = dwarf::lib::evaluator(
                                        	member->get_data_member_location()->at(0), 
                                    	   (*i_child)->get_spec(),
                                    	   std::stack<Dwarf_Unsigned>(
                               	        	std::deque<Dwarf_Unsigned>(1, 0UL))).tos();
                                    	if (containing_offset == 0)
                                    	{
                            	        	// success -- this is admissible
                                        	candidates.push_back(containing_type);
                                    	}
                                	} break;
                                	case DW_TAG_inheritance: {
                                    	auto inheritance = boost::dynamic_pointer_cast<
                                        	spec::inheritance_die>(*i_child);
							        	Dwarf_Off containing_offset = dwarf::lib::evaluator(
			 	                        	inheritance->get_data_member_location()->at(0), 
                                    	   (*i_child)->get_spec(),
                                    	   std::stack<Dwarf_Unsigned>(
                               	        	std::deque<Dwarf_Unsigned>(1, 0UL))).tos();                   
                        	        	if (containing_offset == offset_into_block)
                                    	{
	                                    	candidates.push_back(containing_type);
                                    	}
                                	} break;
                                	default: assert(false); break;
                            	} // end switch
                        	} // end if byte_size
                    	} // end if tag
					} // end for child
                } // end for backref

                switch (candidates.size())
                {
					case 0: goto did_not_understand;
                    case 1: // the good case
		                std::cerr << "Sucessfully resolved pointer at 0x";
        		            std::cerr << std::hex << heap_loc;
                	        std::cerr << " to type ";
                            std::cerr << *candidates.at(0);
                            std::cerr << std::endl;
                        return candidates.at(0);
                    default: // the ambiguous case
		                std::cerr << "Warning: could not unambiguously resolve pointer 0x"
        		            << std::hex << heap_loc
                	        << ". Candidate types are: ";
                        for (auto j = candidates.begin(); j != candidates.end(); j++)
                        {
                            std::cerr << **j << std::endl;
                        }
                        break;
				} // end switch         
                break; // exit for-each-block loop
                did_not_understand:
                	std::cerr << "Warning: did not understand pointer 0x"
                    	<< std::hex << heap_loc
                        << " into heap region beginning 0x" << std::hex << n->begin
	                    << " with size " << n->size << " bytes." << std::endl;
                break;
            } // end else look for byte-scale 
        } // end if block matched
	} // end for each block
}
void process_image::write_type_containment_relation(
	std::multimap<dwarf::lib::Dwarf_Off, dwarf::lib::Dwarf_Off>& out_mm,
	spec::abstract_dieset& ds)
{
	using boost::dynamic_pointer_cast;
	using dwarf::spec::type_die;
	using dwarf::spec::member_die;

	// DEBUG: 
	// HACK: find this dieset in the files table
	boost::optional<std::string> ds_filename;
	for (auto i_file = files.begin(); i_file != files.end(); i_file++)
	{
		if (i_file->second.p_ds.get() == &ds) { ds_filename = i_file->first; break; }
	}
	assert(ds_filename);
	std::cerr << "Building type containment relation (NOT REALLY!) for dieset "
		<< *ds_filename;
	std::cerr << '\n';
	int count = 0;

	/* Write a set of pairs <off1, off2> to out_mm
	 * where off1 and off2 are the offsets of concrete type DIEs
	 * and the type at off2 _immediately contains_ (i.e. instantiates) that at off1. */
	for (auto i_node = ds.begin();
			i_node != ds.end();
			i_node++)
	{
		++count;
		if (count % 100 == 0) std::cerr << '\r' << count;
		//std::cerr << '\r' << ++count;
		if (dynamic_pointer_cast<type_die>(*i_node)
		&&  dynamic_pointer_cast<type_die>(*i_node)->get_concrete_type()
		&&  dynamic_pointer_cast<type_die>(*i_node)->get_concrete_type()->get_offset()
		 == dynamic_pointer_cast<type_die>(*i_node)->get_offset())
		{
			/* Add edges for each type which this DIE _immediately contains_.
			 * To do this, we have to find all types that this DIE immediately contains.
			 * Nested types are not what we're looking for! Instead, we want members
			 * i.e. data type instantiations. */
			for (auto i_child = (*i_node)->children_begin();
						i_child != (*i_node)->children_end();
						i_child++)
			{
				if (dynamic_pointer_cast<member_die>(*i_child)
					&& dynamic_pointer_cast<member_die>(*i_child)->get_type())
				{
					// type *i_node immediately contains type *(*i_child)->get_type()
					auto contained_type
					 = (*(dynamic_pointer_cast<member_die>(*i_child)->get_type()))
					 	->get_concrete_type();
					
					std::cerr << "Type " 
						<< ( (*i_node)->get_name() ? *(*i_node)->get_name() : "(anon)" )
						<< " at " << (*i_node)->get_offset()
						<< " immediately contains type " 
						<< ( contained_type->get_name() ? *contained_type->get_name() : "(anon)" )
						<< " at " << contained_type->get_offset()
						<< std::endl;
						
					out_mm.insert(
						std::make_pair(
							contained_type->get_offset(), 
							(*i_node)->get_offset()
						)
					);
				}
			}
		}
	}
