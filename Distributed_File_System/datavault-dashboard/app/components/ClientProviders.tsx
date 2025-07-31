'use client';

import { useEffect } from 'react';

export default function ClientProviders({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    // Theme detection
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
    function updateTheme() {
      const root = document.documentElement;
      if (prefersDark.matches) {
        root.classList.add('dark');
      } else {
        root.classList.remove('dark');
      }
    }
    updateTheme();
    prefersDark.addEventListener('change', updateTheme);

    // Focus management
    const handleKeydown = (e: KeyboardEvent) => {
      if (e.key === 'Tab') {
        document.body.classList.add('using-keyboard');
      }
    };
    
    const handleMousedown = () => {
      document.body.classList.remove('using-keyboard');
    };

    document.addEventListener('keydown', handleKeydown);
    document.addEventListener('mousedown', handleMousedown);

    // Navigation scroll effects
    const handleScroll = () => {
      const nav = document.querySelector('.apple-nav');
      if (nav) {
        if (window.scrollY > 50) {
          nav.classList.add('apple-nav-scrolled');
        } else {
          nav.classList.remove('apple-nav-scrolled');
        }
      }
    };
    
    window.addEventListener('scroll', handleScroll, { passive: true });

    return () => {
      prefersDark.removeEventListener('change', updateTheme);
      document.removeEventListener('keydown', handleKeydown);
      document.removeEventListener('mousedown', handleMousedown);
      window.removeEventListener('scroll', handleScroll);
    };
  }, []);

  return <>{children}</>;
}
