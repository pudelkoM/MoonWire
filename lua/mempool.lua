local sodium = require "sodium"
local ffi = require "ffi"
local lock = require "lock"
local dpdk_export = require "missing-dpdk-stuff"

local mod = {}

mod.MEMPOOL_F_NO_PHYS_CONTIG = 0x0020

ffi.cdef[[
typedef struct rte_mempool_ctor {} rte_mempool_ctor_t;
typedef struct rte_mempool_obj_cb {} rte_mempool_obj_cb_t;

struct rte_mempool* rte_mempool_create	(	const char * 	name,
unsigned 	n,
unsigned 	elt_size,
unsigned 	cache_size,
unsigned 	private_data_size,
rte_mempool_ctor_t * 	mp_init,
void * 	mp_init_arg,
rte_mempool_obj_cb_t * 	obj_init,
void * 	obj_init_arg,
int 	socket_id,
unsigned 	flags 
);
]]

function mod.createMempool(n, elt_size, socket_id, fn)
    local pool = ffi.C.rte_mempool_create("", n, elt_size, 0, 0, nil, nil, nil, nil, socket_id, mod.MEMPOOL_F_NO_PHYS_CONTIG)
    
    if fn then
        bufs = pool:bufArray(n)
        bufs:allocN(n)
        for i = 1, n do
            fn(bufs[i], pool)
        end
        bufs:free(n)
    end

    return pool
end

local mempool = {}

local bufArray = {}

--- Create a new array of memory buffers (initialized to nil).
function mempool:bufArray(n)
	n = n or 63
	return setmetatable({
		size = n,
		maxSize = n,
		array = ffi.new("void*[?]", n),
		mem = self,
	}, bufArray)
end

function bufArray:resize(size)
	if size > self.maxSize then
		-- TODO: consider reallocing the struct here
		log:fatal("enlarging a bufArray is currently not supported")
	end
	self.size = size
end

function bufArray:allocN(num)
    self:resize(num)
    dpdk_export.rte_mempool_get_bulk_export(self.mem, ffi.cast("void**", self.array), self.size)
end

--- Free the first n buffers.
function bufArray:free(n)
    dpdk_export.rte_mempool_put_bulk_export(self.mem, ffi.cast("void**", self.array), n)
end

function bufArray.__index(self, k)
	-- TODO: is this as fast as I hope it to be?
	return type(k) == "number" and self.array[k - 1] or bufArray[k]
end

mempool.__index = mempool
ffi.metatype("struct rte_mempool", mempool)

return mod
