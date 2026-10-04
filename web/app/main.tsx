import { createRoot } from 'react-dom/client';
import Console from './page';
import './globals.css';
import './console.css';
import './workspace.css';
import './diagnostics.css';
import './interface.css';
import './workspace-refinement.css';
import './message-search.css';
import './filter-workspace.css';
import './message-analysis.css';

createRoot(document.getElementById('root')!).render(<Console />);
