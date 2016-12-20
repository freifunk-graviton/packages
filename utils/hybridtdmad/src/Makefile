all: hybridtdma

hybridtdma: gravitonhmac.cpp
	$(CXX) $(CXXFLAGS) gravitonhmac.cpp -o hybridtdma -I$(BUILD_DIR)/uClibc++/include/ -I$(BUILD_DIR)/libnl-tiny/include/ -DCONFIG_LIBNL30 $(LIBS) -levent -lnl-tiny -lzmq -lpthread

# remove object files and executable when user executes "make clean"
clean:
	rm *.o hybridtdma
