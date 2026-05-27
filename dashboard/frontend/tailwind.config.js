/* @type {import('tailwindcss).Config} */
export default{
    content: ['./index.html', './src/**/*{js, jsx}'],
    theme: {
        extend: {
            colors: {
                sentinel: {
                    bg:      '#0f172a',
                    card:    '#1e293b',
                    border:  '#334155',
                    muted:   '#94a3b8',
                    primary: '#3b82f6',
                }
            },
        },
    },
    plugins: [],
    
}