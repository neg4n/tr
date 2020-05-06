#include <memory>
#define TRICKSTER_DEBUG
#include <tr.hpp>

int main( ) {
  auto ctx = std::make_unique<tr::process_t>( "trtest" );
  printf( "%i\n", ctx->get_id( ) );
}