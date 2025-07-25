'use client';

import CollaborativeEditor from '../../../../components/collaboration/CollaborativeEditor';

interface EditorPageProps {
  params: { documentId: string };
}

export default function EditorPage({ params }: EditorPageProps) {
  return (
    <CollaborativeEditor
      documentId={params.documentId}
      currentUserId="current-user"
      currentUserName="Current User"
    />
  );
}
