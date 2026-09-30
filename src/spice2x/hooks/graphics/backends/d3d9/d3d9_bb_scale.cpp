#include "d3d9_bb_scale.h"

#include "avs/game.h"
#include "hooks/graphics/graphics.h"
#include "util/logging.h"

namespace d3d9_bb_scale {
namespace {

bool enabled = false;
UINT game_bb_width = 0;
UINT game_bb_height = 0;

IDirect3DTexture9 *rt_texture = nullptr;
IDirect3DSurface9 *rt_surface = nullptr;
IDirect3DSurface9 *rt_orig_surface = nullptr;

void release_resources() {
    if (rt_orig_surface) {
        rt_orig_surface->Release();
        rt_orig_surface = nullptr;
    }
    if (rt_surface) {
        rt_surface->Release();
        rt_surface = nullptr;
    }
    if (rt_texture) {
        rt_texture->Release();
        rt_texture = nullptr;
    }
}

bool create_resources(IDirect3DDevice9 *device, D3DFORMAT format) {
    release_resources();

    if (!device || game_bb_width == 0 || game_bb_height == 0) {
        return false;
    }

    HRESULT hr = device->CreateTexture(
            game_bb_width,
            game_bb_height,
            1,
            D3DUSAGE_RENDERTARGET,
            format,
            D3DPOOL_DEFAULT,
            &rt_texture,
            nullptr);
    if (FAILED(hr) || !rt_texture) {
        log_warning("graphics::d3d9",
                "bb_scale: CreateTexture {}x{} failed, hr={}",
                game_bb_width, game_bb_height, FMT_HRESULT(hr));
        release_resources();
        return false;
    }

    hr = rt_texture->GetSurfaceLevel(0, &rt_surface);
    if (FAILED(hr) || !rt_surface) {
        log_warning("graphics::d3d9",
                "bb_scale: GetSurfaceLevel failed, hr={}", FMT_HRESULT(hr));
        release_resources();
        return false;
    }

    hr = device->GetRenderTarget(0, &rt_orig_surface);
    if (FAILED(hr) || !rt_orig_surface) {
        log_warning("graphics::d3d9",
                "bb_scale: GetRenderTarget failed, hr={}", FMT_HRESULT(hr));
        release_resources();
        return false;
    }

    hr = device->SetRenderTarget(0, rt_surface);
    if (FAILED(hr)) {
        log_warning("graphics::d3d9",
                "bb_scale: initial SetRenderTarget failed, hr={}", FMT_HRESULT(hr));
        release_resources();
        return false;
    }

    log_info("graphics::d3d9",
            "bb_scale: game RT {}x{} → backbuffer (linear StretchRect before Present)",
            game_bb_width, game_bb_height);
    return true;
}

} // namespace

bool should_enable() {
    if (!GRAPHICS_WINDOWED || !avs::game::is_model({"GLD", "HDD", "I00", "JDJ"})) {
        return false;
    }
    if (!GRAPHICS_WINDOW_SIZE.has_value()) {
        return false;
    }
    const auto &size = GRAPHICS_WINDOW_SIZE.value();
    return size.first == 854 && size.second == 480;
}

bool active() {
    return enabled && rt_surface != nullptr && rt_orig_surface != nullptr;
}

bool apply_presentation_params(D3DPRESENT_PARAMETERS *pp) {
    enabled = false;
    if (!pp || !should_enable()) {
        return false;
    }

    game_bb_width = pp->BackBufferWidth;
    game_bb_height = pp->BackBufferHeight;

    const auto win_w = GRAPHICS_WINDOW_SIZE.value().first;
    const auto win_h = GRAPHICS_WINDOW_SIZE.value().second;

    if (game_bb_width == 0 || game_bb_height == 0
            || (game_bb_width == win_w && game_bb_height == win_h)) {
        return false;
    }

    log_info("graphics::d3d9",
            "bb_scale: BackBuffer {}x{} → {}x{} (Present 1:1, filtered stretch)",
            game_bb_width, game_bb_height, win_w, win_h);

    pp->BackBufferWidth = win_w;
    pp->BackBufferHeight = win_h;
    enabled = true;
    return true;
}

void restore_presentation_params(D3DPRESENT_PARAMETERS *pp) {
    if (!pp || !enabled || game_bb_width == 0 || game_bb_height == 0) {
        return;
    }
    pp->BackBufferWidth = game_bb_width;
    pp->BackBufferHeight = game_bb_height;
}

bool on_device_created(IDirect3DDevice9 *device, D3DPRESENT_PARAMETERS *pp) {
    if (!enabled || !device || !pp) {
        return false;
    }
    if (!create_resources(device, pp->BackBufferFormat)) {
        enabled = false;
        return false;
    }
    return true;
}

void on_device_reset_invalidate() {
    release_resources();
}

bool on_device_reset_recreate(IDirect3DDevice9 *device, D3DPRESENT_PARAMETERS *pp) {
    if (!enabled || !device || !pp) {
        return false;
    }
    if (!create_resources(device, pp->BackBufferFormat)) {
        enabled = false;
        return false;
    }
    return true;
}

void on_device_release() {
    release_resources();
    enabled = false;
    game_bb_width = 0;
    game_bb_height = 0;
}

void on_begin_scene(IDirect3DDevice9 *device) {
    if (!active() || !device) {
        return;
    }
    const HRESULT hr = device->SetRenderTarget(0, rt_surface);
    if (FAILED(hr)) {
        log_warning("graphics::d3d9",
                "bb_scale: BeginScene SetRenderTarget failed, hr={}", FMT_HRESULT(hr));
    }
}

void on_present(IDirect3DDevice9 *device) {
    if (!active() || !device) {
        return;
    }

    RECT src {
        0,
        0,
        static_cast<LONG>(game_bb_width),
        static_cast<LONG>(game_bb_height),
    };

    HRESULT hr = device->StretchRect(
            rt_surface,
            &src,
            rt_orig_surface,
            nullptr,
            D3DTEXF_LINEAR);
    if (FAILED(hr)) {
        log_warning("graphics::d3d9",
                "bb_scale: StretchRect failed, hr={}", FMT_HRESULT(hr));
    }

    hr = device->SetRenderTarget(0, rt_orig_surface);
    if (FAILED(hr)) {
        log_warning("graphics::d3d9",
                "bb_scale: Present SetRenderTarget failed, hr={}", FMT_HRESULT(hr));
    }
}

bool try_get_back_buffer(
        UINT iSwapChain,
        UINT iBackBuffer,
        D3DBACKBUFFER_TYPE Type,
        IDirect3DSurface9 **ppBackBuffer)
{
    if (!active()
            || iSwapChain != 0
            || iBackBuffer != 0
            || Type != D3DBACKBUFFER_TYPE_MONO
            || ppBackBuffer == nullptr) {
        return false;
    }

    rt_surface->AddRef();
    *ppBackBuffer = rt_surface;
    return true;
}

} // namespace d3d9_bb_scale
