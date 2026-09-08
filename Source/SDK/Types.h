#pragma once
#include "Global.h"


namespace app
{
	enum class eTextCase : uint8_t
	{
		Title,
		Small,
		Caps
	};

	enum class eTextDirection : uint8_t
	{
		Forward,
		Backward
	};

	struct Float2
	{
		float x, y;
	}; 

	struct Color
	{
		int r, g, b, a; 
		
		Color(int r, int g, int b, int a = 255)
			: r(r), g(g), b(b), a(a)
		{
		}

		Color(float r, float g, float b, float a = 255)
			: r(static_cast<int>(r * 255.0f)),
			g(static_cast<int>(g * 255.0f)),
			b(static_cast<int>(b * 255.0f)),
			a(static_cast<int>(a * 255.0f))
		{
		}

		Color& operator=(const Color& other) {
			if (this != &other) {
				r = other.r;
				g = other.g;
				b = other.b;
				a = other.a;
			}
			return *this;
		}

		Color(std::uint32_t hex_color, int alpha = 255)
			: r((hex_color >> 16) & 0xFF),
			g((hex_color >> 8) & 0xFF),
			b(hex_color & 0xFF),
			a(alpha) {
		}

		Color(std::uint32_t hex_color, float alpha)
			: r((hex_color >> 16) & 0xFF),
			g((hex_color >> 8) & 0xFF),
			b(hex_color & 0xFF),
			a(static_cast<int>(alpha * 255.0f)) {
		}


		Color(const Color& clr, int alpha)
			: r(clr.r), g(clr.g), b(clr.b), a(alpha) {
		}

		Color(const Color& clr, float alpha)
			: r(clr.r), g(clr.g), b(clr.b), a(static_cast<int>(alpha * 255.0f)) {
		}

		Color operator*(float factor) const {
			return Color(r, g, b, static_cast<int>(a * factor));
		}

		std::uint32_t pack() const {
			return (a << 24) | (b << 16) | (g << 8) | r;
		}
	};
}