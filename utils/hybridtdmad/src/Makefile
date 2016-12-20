all: hybridtdma
	
hybridtdma: gravitonhmac.o
	$(CXX) $(LDFLAGS) gravitonhmac.o -o hybridtdma -I$(BUILD_DIR)/uClibc++/include/ -I$(BUILD_DIR)/libnl-tiny/include/ -DCONFIG_LIBNL30 $(LIBS) -levent -lnl-tiny -lzmq -lpthread
gravitonhmac.o: gravitonhmac.cpp
	$(CXX) $(CXXFLAGS) -c gravitonhmac.cpp -I$(BUILD_DIR)/uClibc++/include/ -I$(BUILD_DIR)/libnl-tiny/include/ -DCONFIG_LIBNL30 $(LIBS)

# remove object files and executable when user executes "make clean"
clean:
	rm *.o hybridtdma
