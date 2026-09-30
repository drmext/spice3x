#pragma once

#include <d3d9.h>

// IIDX 14-17 arcade widescreen: game draws into a 640x480 RT; we StretchRect LINEAR into
// an 854x480 backbuffer so Present is 1:1 (bilinear, not driver Present stretch).
namespace d3d9_bb_scale {

bool should_enable();
bool active();

// Before CreateDevice / Reset: bump BB to GRAPHICS_WINDOW_SIZE when gated.
bool apply_presentation_params(D3DPRESENT_PARAMETERS *pp);

// After CreateDevice / Reset: put native game size back into the params the game sees.
void restore_presentation_params(D3DPRESENT_PARAMETERS *pp);

bool on_device_created(IDirect3DDevice9 *device, D3DPRESENT_PARAMETERS *pp);

void on_device_reset_invalidate();
bool on_device_reset_recreate(IDirect3DDevice9 *device, D3DPRESENT_PARAMETERS *pp);

void on_device_release();

void on_begin_scene(IDirect3DDevice9 *device);

// StretchRect LINEAR RT → real BB, then SetRenderTarget to BB (before overlay).
void on_present(IDirect3DDevice9 *device);

// Redirect swapchain-0 GetBackBuffer to the game RT when active.
bool try_get_back_buffer(
        UINT iSwapChain,
        UINT iBackBuffer,
        D3DBACKBUFFER_TYPE Type,
        IDirect3DSurface9 **ppBackBuffer);

// Native (pre-scale) backbuffer size used for IIDX 9-13 GetClientRect viewport.
bool native_size(UINT *width, UINT *height);

} // namespace d3d9_bb_scale
