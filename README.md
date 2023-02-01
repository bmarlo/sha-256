## Usage

```C++
#include <marlo/sha256.hpp>
#include <iostream>

int main(int argc, char** argv)
{
    marlo::sha256 ctx;
    for (int i = 1; i < argc - 1; i++) {
        ctx.update(argv[i]);
    }

    std::cout << ctx.finalize(argc > 1 ? argv[argc - 1] : "") << '\n';
    return 0;
}
```
