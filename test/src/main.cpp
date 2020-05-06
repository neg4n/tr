#include <memory>
// Enable logging
#define TRICKSTER_DEBUG
#include <tr.hpp>

constexpr std::uintptr_t value_address = 0x7ffce9fb1a34;

int main( ) {
  // Create process object
  auto ctx = std::make_unique<tr_process_t>( "trtest" );
  // Print its id
  printf( "%i\n", ctx->get_id( ) );
  // Map memory regions
  ctx->map_memory_regions( );
  // Print modules loaded into process memory (without duplicate segments)
  for ( const auto & module : tr_get_modules_list( ctx->get_memory_regions( ) ) ) {
    printf( "%s", module.c_str( ) );
  }
  // Read integer value at 0x7ffce9fb1a34
  const auto read_opt = ctx->read_memory<int>( value_address );
  if ( read_opt.has_value( ) ) {
    printf( "%i", read_opt.value( ) );
  }
  // Write integer value (20) at 0x7ffce9fb1a34
  ctx->write_memory( value_address, 20 );
}
