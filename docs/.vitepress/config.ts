import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'JED Framework',
  description: 'AI Agent Security Competition - Jailbreak, Exploit, Defend',
  base: '/competitionscratch/',
  ignoreDeadLinks: true,
  
  themeConfig: {
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Getting Started', link: '/GETTING_STARTED' },
      { text: 'Guides', link: '/GUARDRAILS_GUIDE' },
      { text: 'API', link: '/API_REFERENCE' },
      { 
        text: 'GitHub', 
        link: 'https://github.com/mbhatt1/competitionscratch' 
      }
    ],

    sidebar: [
      {
        text: 'Introduction',
        items: [
          { text: 'Overview', link: '/README' },
          { text: 'Getting Started', link: '/GETTING_STARTED' },
          { text: 'FAQ', link: '/FAQ' }
        ]
      },
      {
        text: 'Competition',
        items: [
          { text: 'Rules', link: '/COMPETITION_RULES' },
          { text: 'Scoring', link: '/SCORING' },
          { text: 'Design', link: '/COMPETITION_DESIGN' }
        ]
      },
      {
        text: 'Development',
        items: [
          { text: 'Guardrails Guide', link: '/GUARDRAILS_GUIDE' },
          { text: 'Attacks Guide', link: '/ATTACKS_GUIDE' },
          { text: 'Testing Guide', link: '/TESTING_GUIDE' }
        ]
      },
      {
        text: 'Reference',
        items: [
          { text: 'API Reference', link: '/API_REFERENCE' }
        ]
      }
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/mbhatt1/competitionscratch' }
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2026 JED Framework Contributors'
    },

    search: {
      provider: 'local'
    },

    editLink: {
      pattern: 'https://github.com/mbhatt1/competitionscratch/edit/master/docs/:path',
      text: 'Edit this page on GitHub'
    }
  },

  markdown: {
    lineNumbers: true,
    theme: {
      light: 'github-light',
      dark: 'github-dark'
    }
  },

  lastUpdated: true
})
